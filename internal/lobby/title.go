package lobby

import "github.com/princebyyourlogic/angelware/internal/bitbuf"

// Title utilities, lobby service 12 (senders LBYM 0x71430..0x71840, results
// 0x71ab0). Only task 1 has a caller in the game:
//
//	1 verify string(u8, string) -> bool valid (0x71d28; the client takes the count as 1)
//
// It backs lobby task 0x39 (FUN_00010400), DemonWare's verifyString. Every string
// is accepted; a word filter would go here. Tasks 2-4 are never sent.
const titleVerifyString = 1

func (c *Conn) title(t Task) []byte {
	if t.ID == titleVerifyString {
		if fields, err := t.Args.Fields(); err == nil && len(fields) > 1 {
			c.log.Debug("string verified", "text", string(fields[1].Bytes))
		}
		return Reply(t, []bitbuf.Field{bitbuf.Int(bitbuf.Bool, 1)})
	}
	c.log.Info("title utilities task not implemented", "task", t.ID)
	return Reply(t, nil)
}
