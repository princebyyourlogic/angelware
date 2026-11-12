package lobby

import (
	"context"
	"errors"

	"github.com/princebyyourlogic/angelware/internal/bitbuf"
	"github.com/princebyyourlogic/angelware/internal/store"
)

// Storage, lobby service 10 (senders LBYM 0x70808..0x70f98, CDWStorageProcess;
// used for trades). Results (0x71090): tasks 1 and 5 carry one object, 7 and 8 a
// u32 count and that many file infos.
//
//	1 upload(u8, bool flag, string name, bool private, blob data)  -> u64 file id (0x712a0)
//	2 update data(u8, u64 file, blob data)
//	3 update params(u8, u64 file, string name, bool private)
//	4 remove(u8, u64 file)
//	5 download(u8, u64 file)                -> file info + blob data (0x701f8)
//	7 list by user(u8, u64 user, u32 offset, u16 count) -> list entries
//	8 list by publisher(u8, u32 offset, u16 count)      -> list entries (title content)
//
// A list entry (0x6fdc8) is u32 file size followed by the file info.
//
// File info (0x70470): u64 id, u32 created, u32 modified, bool flag, bool private,
// u64 owner, string name (<= 127). The flag is echoed as the upload sent it. The
// visibility bit is 0 for public (as in DemonWare's BD_VISIBLE_PUBLIC = 0).
//
// Trade flow (OME2 0x12ef8): the host lists its own files, removes each one, then
// uploads the created superstar (5184 bytes); the joiner lists the host's files
// and downloads the first into a 0x1440-byte buffer.
const (
	stUpload    = 1
	stUpdate    = 2
	stParams    = 3
	stRemove    = 4
	stDownload  = 5
	stByUser    = 7
	stPublisher = 8

	// A whole gateway frame has a 16-bit length, so a file must fit in one.
	maxFileSize  = 60000
	maxFileList  = 50
	storageError = 1 // any non-zero error fails the request on the client
)

func boolField(b bool) bitbuf.Field {
	if b {
		return bitbuf.Int(bitbuf.Bool, 1)
	}
	return bitbuf.Int(bitbuf.Bool, 0)
}

func fileInfo(f store.File) []bitbuf.Field {
	return []bitbuf.Field{
		bitbuf.Int(bitbuf.U64, f.ID),
		bitbuf.Int(bitbuf.U32, uint64(f.Created.Unix())),
		bitbuf.Int(bitbuf.U32, uint64(f.Modified.Unix())),
		boolField(f.Flag), boolField(!f.Visible),
		bitbuf.Int(bitbuf.U64, f.Owner),
		bitbuf.Bytes(bitbuf.String, []byte(truncate(f.Name, 127))),
	}
}

func (c *Conn) storage(ctx context.Context, t Task) []byte {
	fields, err := t.Args.Fields()
	if err != nil || len(fields) < 1 {
		c.log.Warn("storage task did not parse", "task", t.ID, "err", err)
		return ErrorReply(t, storageError)
	}
	args := fields[1:]
	st, me := c.srv.Store, c.sess.UserID
	arg := func(i int, typ uint8) (bitbuf.Field, bool) {
		if i < len(args) && args[i].Type == typ {
			return args[i], true
		}
		return bitbuf.Field{}, false
	}

	switch t.ID {
	case stUpload:
		flag, ok1 := arg(0, bitbuf.Bool)
		name, ok2 := arg(1, bitbuf.String)
		private, ok3 := arg(2, bitbuf.Bool)
		data, ok4 := arg(3, bitbuf.Blob)
		if !ok1 || !ok2 || !ok3 || !ok4 || len(data.Bytes) > maxFileSize {
			c.log.Warn("upload refused", "fields", len(args), "size", len(data.Bytes))
			return ErrorReply(t, storageError)
		}
		id, err := st.CreateFile(ctx, store.File{Owner: me, Name: string(name.Bytes), Flag: flag.Int != 0,
			Visible: private.Int == 0, Data: data.Bytes})
		if err != nil {
			c.log.Error("save upload", "err", err)
			return ErrorReply(t, storageError)
		}
		c.log.Info("file uploaded", "file", id, "name", string(name.Bytes), "size", len(data.Bytes))
		return Reply(t, []bitbuf.Field{bitbuf.Int(bitbuf.U64, id)})
	case stUpdate:
		id, ok1 := arg(0, bitbuf.U64)
		data, ok2 := arg(1, bitbuf.Blob)
		if !ok1 || !ok2 || len(data.Bytes) > maxFileSize {
			return ErrorReply(t, storageError)
		}
		if ok, err := st.UpdateFile(ctx, me, id.Int, data.Bytes, nil, false); !ok || err != nil {
			return ErrorReply(t, storageError)
		}
		return Reply(t, nil)
	case stParams:
		id, ok1 := arg(0, bitbuf.U64)
		name, ok2 := arg(1, bitbuf.String)
		private, ok3 := arg(2, bitbuf.Bool)
		if !ok1 || !ok2 || !ok3 {
			return ErrorReply(t, storageError)
		}
		n := string(name.Bytes)
		if ok, err := st.UpdateFile(ctx, me, id.Int, nil, &n, private.Int == 0); !ok || err != nil {
			return ErrorReply(t, storageError)
		}
		return Reply(t, nil)
	case stRemove:
		if id, ok := arg(0, bitbuf.U64); ok {
			if err := st.DeleteFile(ctx, me, id.Int); err != nil {
				c.log.Error("remove file", "err", err)
			}
		}
		return Reply(t, nil)
	case stDownload:
		id, ok := arg(0, bitbuf.U64)
		if !ok {
			return ErrorReply(t, storageError)
		}
		f, err := st.File(ctx, id.Int)
		if err != nil || (!f.Visible && f.Owner != me) {
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				c.log.Error("load file", "err", err)
			}
			return ErrorReply(t, storageError)
		}
		c.log.Info("file downloaded", "file", f.ID, "owner", f.Owner)
		return Reply(t, append(fileInfo(f), bitbuf.Bytes(bitbuf.Blob, f.Data)))
	case stByUser:
		user, ok := arg(0, bitbuf.U64)
		if !ok {
			return ListReply(t, 0, nil)
		}
		offset, limit := 0, maxFileList
		if v, ok := arg(1, bitbuf.U32); ok {
			offset = int(v.Int)
		}
		if v, ok := arg(2, bitbuf.U16); ok && int(v.Int) < limit {
			limit = int(v.Int)
		}
		files, err := st.FilesByOwner(ctx, user.Int, user.Int == me, offset, limit)
		if err != nil {
			c.log.Error("list files", "err", err)
		}
		var out []bitbuf.Field
		for _, f := range files {
			out = append(out, bitbuf.Int(bitbuf.U32, uint64(f.Size)))
			out = append(out, fileInfo(f)...)
		}
		return ListReply(t, uint32(len(files)), out)
	case stPublisher:
		return ListReply(t, 0, nil) // no title-published content
	}
	c.log.Info("storage task not implemented", "task", t.ID)
	return Reply(t, nil)
}
