package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type cellKey struct {
	proto string
	mode  string
	wl    string
	conns string
}

type sample struct {
	rps     float64
	p99     float64
	mean    float64
	cpu     float64
	rss     float64
	mallocs float64
	bytes   float64
	bound   bool
}

type cellStats struct {
	runs    int
	invalid int
	rps     float64
	rpsMin  float64
	rpsMax  float64
	p99     float64
	mean    float64
	cpu     float64
	rss     float64
	mallocs float64
	bytes   float64
	bound   bool
	note    string
}

var workloadOrder = []string{"W1", "W1r", "W2", "W3", "W4", "W5a", "W5b", "W6", "W7g", "W7b", "W8", "W9", "W10", "W11", "W12a", "W12b"}
var protoOrder = []string{"h1", "tls", "h2c", "h2"}

func main() {
	alos := flag.String("alos", "", "ALOS framework name to compute margins for (e.g. alos-base)")
	base := flag.String("base", "", "with -lab: ALOS baseline name for a before/after table")
	lab := flag.String("lab", "", "with -base: ALOS changed-tree name")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: report [-alos name] [-base name -lab name] results.csv ...")
		os.Exit(2)
	}
	data := map[string]map[cellKey][]sample{}
	invalid := map[string]map[cellKey]int{}
	notes := map[string]map[cellKey]string{}
	for _, path := range flag.Args() {
		if err := load(path, data, invalid, notes); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	stats := summarize(data, invalid, notes)
	if *base != "" && *lab != "" {
		printBeforeAfter(stats, *base, *lab)
		return
	}
	printMatrix(stats, *alos)
}

func load(path string, data map[string]map[cellKey][]sample, invalid map[string]map[cellKey]int, notes map[string]map[cellKey]string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fw := rec[col["fw"]]
		key := cellKey{rec[col["proto"]], rec[col["mode"]], rec[col["wl"]], rec[col["conns"]]}
		if data[fw] == nil {
			data[fw] = map[cellKey][]sample{}
			invalid[fw] = map[cellKey]int{}
			notes[fw] = map[cellKey]string{}
		}
		if rec[col["valid"]] != "1" {
			invalid[fw][key]++
			notes[fw][key] = rec[col["note"]]
			continue
		}
		data[fw][key] = append(data[fw][key], sample{
			rps:     num(rec[col["rps"]]),
			p99:     num(rec[col["p99_us"]]),
			mean:    num(rec[col["mean_us"]]),
			cpu:     num(rec[col["server_cpu_pct"]]),
			rss:     num(rec[col["server_rss_max_kb"]]),
			mallocs: num(rec[col["mallocs_per_req"]]),
			bytes:   num(rec[col["bytes_per_req"]]),
			bound:   rec[col["client_bound"]] == "1",
		})
	}
}

func num(s string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return v
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func pick(ss []sample, f func(sample) float64) []float64 {
	out := make([]float64, len(ss))
	for i, s := range ss {
		out[i] = f(s)
	}
	return out
}

func summarize(data map[string]map[cellKey][]sample, invalid map[string]map[cellKey]int, notes map[string]map[cellKey]string) map[string]map[cellKey]cellStats {
	out := map[string]map[cellKey]cellStats{}
	for fw, cells := range invalid {
		out[fw] = map[cellKey]cellStats{}
		for key, n := range cells {
			out[fw][key] = cellStats{invalid: n, note: notes[fw][key]}
		}
	}
	for fw, cells := range data {
		for key, ss := range cells {
			rps := pick(ss, func(s sample) float64 { return s.rps })
			st := out[fw][key]
			st.runs = len(ss)
			st.rps = median(rps)
			st.rpsMin = slices.Min(rps)
			st.rpsMax = slices.Max(rps)
			st.p99 = median(pick(ss, func(s sample) float64 { return s.p99 }))
			st.mean = median(pick(ss, func(s sample) float64 { return s.mean }))
			st.cpu = median(pick(ss, func(s sample) float64 { return s.cpu }))
			st.rss = slices.Max(pick(ss, func(s sample) float64 { return s.rss }))
			st.mallocs = median(pick(ss, func(s sample) float64 { return s.mallocs }))
			st.bytes = median(pick(ss, func(s sample) float64 { return s.bytes }))
			st.bound = slices.ContainsFunc(ss, func(s sample) bool { return s.bound })
			out[fw][key] = st
		}
	}
	return out
}

func sortedKeys(stats map[string]map[cellKey]cellStats) []cellKey {
	seen := map[cellKey]bool{}
	for _, cells := range stats {
		for k := range cells {
			seen[k] = true
		}
	}
	keys := make([]cellKey, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.proto != b.proto {
			return slices.Index(protoOrder, a.proto) < slices.Index(protoOrder, b.proto)
		}
		if a.wl != b.wl {
			return slices.Index(workloadOrder, a.wl) < slices.Index(workloadOrder, b.wl)
		}
		ca, _ := strconv.Atoi(a.conns)
		cb, _ := strconv.Atoi(b.conns)
		return ca < cb
	})
	return keys
}

func fwNames(stats map[string]map[cellKey]cellStats, alos string) []string {
	names := make([]string, 0, len(stats))
	for fw := range stats {
		names = append(names, fw)
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i] == alos || names[j] == alos {
			return names[i] == alos
		}
		return names[i] < names[j]
	})
	return names
}

func formatRPS(v float64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.2fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fk", v/1e3)
	default:
		return fmt.Sprintf("%.0f", v)
	}
}

func cellText(st cellStats, ok bool) string {
	if !ok {
		return "—"
	}
	if st.runs == 0 {
		return "n/a (" + shorten(st.note) + ")"
	}
	s := formatRPS(st.rps)
	if st.bound {
		s += "†"
	}
	if st.invalid > 0 {
		s += fmt.Sprintf(" (%d invalid)", st.invalid)
	}
	return s
}

func shorten(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

func printMatrix(stats map[string]map[cellKey]cellStats, alos string) {
	names := fwNames(stats, alos)
	keys := sortedKeys(stats)
	current := ""
	for _, k := range keys {
		if k.proto != current {
			current = k.proto
			fmt.Printf("\n### %s\n\n| workload | conns |", k.proto)
			for _, n := range names {
				fmt.Printf(" %s |", n)
			}
			fmt.Print(" winner | ALOS vs best competitor |\n|---|---|")
			for range names {
				fmt.Print("---|")
			}
			fmt.Print("---|---|\n")
		}
		label := k.wl
		if k.mode == "proxy" {
			label += " (proxy)"
		}
		fmt.Printf("| %s | %s |", label, k.conns)
		best, bestRPS, bestOther, bestOtherRPS := "", 0.0, "", 0.0
		for _, n := range names {
			st, ok := stats[n][k]
			fmt.Printf(" %s |", cellText(st, ok))
			if ok && st.runs > 0 {
				if st.rps > bestRPS {
					best, bestRPS = n, st.rps
				}
				if !strings.HasPrefix(n, "alos-") && st.rps > bestOtherRPS {
					bestOther, bestOtherRPS = n, st.rps
				}
			}
		}
		margin := "—"
		if a, ok := stats[alos][k]; ok && a.runs > 0 && bestOtherRPS > 0 {
			margin = fmt.Sprintf("%+.1f%% vs %s", (a.rps/bestOtherRPS-1)*100, bestOther)
		}
		fmt.Printf(" %s | %s |\n", best, margin)
	}
	fmt.Println("\n† load generator CPU-saturated in at least one run (client-bound).")
	printResources(stats, names, keys)
}

func printResources(stats map[string]map[cellKey]cellStats, names []string, keys []cellKey) {
	fmt.Print("\n### Latency, CPU, memory and allocations (medians)\n\n| proto | workload | conns | fw | p99 µs | mean µs | server CPU % | peak RSS MB | mallocs/req | bytes/req |\n|---|---|---|---|---|---|---|---|---|---|\n")
	for _, k := range keys {
		for _, n := range names {
			st, ok := stats[n][k]
			if !ok || st.runs == 0 {
				continue
			}
			fmt.Printf("| %s | %s | %s | %s | %s | %s | %.0f | %.1f | %s | %s |\n", k.proto, k.wl, k.conns, n,
				orDash(st.p99, "%.0f"), orDash(st.mean, "%.0f"), st.cpu, st.rss/1024, orDash(st.mallocs, "%.3f"), orDash(st.bytes, "%.0f"))
		}
	}
}

func orDash(v float64, format string) string {
	if v == 0 {
		return "—"
	}
	return fmt.Sprintf(format, v)
}

func printBeforeAfter(stats map[string]map[cellKey]cellStats, base, lab string) {
	keys := sortedKeys(stats)
	fmt.Printf("| proto | workload | conns | %s req/s | %s req/s | Δ req/s | runs range (%s) | Δ p99 | Δ mallocs/req | Δ peak RSS |\n|---|---|---|---|---|---|---|---|---|---|\n", base, lab, lab)
	for _, k := range keys {
		b, bok := stats[base][k]
		l, lok := stats[lab][k]
		if !bok || !lok || b.runs == 0 || l.runs == 0 {
			continue
		}
		fmt.Printf("| %s | %s | %s | %s | %s | %+.1f%% | %s–%s | %s | %s | %s |\n", k.proto, k.wl, k.conns,
			formatRPS(b.rps), formatRPS(l.rps), (l.rps/b.rps-1)*100, formatRPS(l.rpsMin), formatRPS(l.rpsMax),
			pct(b.p99, l.p99), diff(b.mallocs, l.mallocs), pct(b.rss, l.rss))
	}
}

func pct(a, b float64) string {
	if a == 0 || b == 0 {
		return "—"
	}
	return fmt.Sprintf("%+.1f%%", (b/a-1)*100)
}

func diff(a, b float64) string {
	if a == 0 && b == 0 {
		return "0"
	}
	return fmt.Sprintf("%+.3f", b-a)
}
