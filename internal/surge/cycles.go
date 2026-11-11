package surge

import "fmt"

// breakGroupCycles removes group->group member references that form
// a cycle. A depth-first walk marks the current path; an edge that
// points back onto the path is a back-edge and gets cut (with a
// report note). Groups left with no members fall back to direct,
// mirroring convertGroup's empty-group handling.
func breakGroupCycles(imp *Imported, rep *Report) {
	byName := map[string]*GroupDef{}
	for i := range imp.Groups {
		byName[imp.Groups[i].Name] = &imp.Groups[i]
	}
	const (
		white = 0 // unvisited
		grey  = 1 // on the current DFS path
		black = 2 // fully explored
	)
	color := map[string]int{}
	var visit func(g *GroupDef)
	visit = func(g *GroupDef) {
		color[g.Name] = grey
		kept := g.Members[:0]
		for _, m := range g.Members {
			_, isGroup := byName[m]
			if isGroup {
				if color[m] == grey {
					rep.Notes = append(rep.Notes,
						fmt.Sprintf("组「%s」对组「%s」的循环引用已断开（sing-box 不接受循环依赖）", g.Name, m))
					continue
				}
			}
			kept = append(kept, m)
		}
		g.Members = kept
		for _, m := range g.Members {
			if child, isGroup := byName[m]; isGroup && color[m] == white {
				visit(child)
			}
		}
		if len(g.Members) == 0 {
			g.Members = []string{"direct"}
			rep.Notes = append(rep.Notes,
				fmt.Sprintf("组「%s」断开循环引用后无可用成员，已回退为仅直连", g.Name))
		}
		color[g.Name] = black
	}
	for i := range imp.Groups {
		if color[imp.Groups[i].Name] == white {
			visit(&imp.Groups[i])
		}
	}
}
