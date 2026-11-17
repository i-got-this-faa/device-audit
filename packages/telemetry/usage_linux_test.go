//go:build linux

package telemetry

import "testing"

func TestParseProcStatAndOSRelease(t *testing.T) {
	stat := "12 (worker) S) S 1 1 1 0 -1 0 1 2 3 4 15 16 0 0 20 0 1 0 10 100 99 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22\n"
	utime, stime, rss, err := parseProcStat(stat)
	if err != nil {
		t.Fatal(err)
	}
	if utime != 15 || stime != 16 || rss != 99 {
		t.Fatalf("utime=%d stime=%d rss=%d", utime, stime, rss)
	}
	if _, _, _, err := parseProcStat("no-command"); err == nil {
		t.Fatal("missing command was accepted")
	}
	id, version := parseOSRelease("NAME=\"Example\"\nID=example\nVERSION_ID=\"1.2\"\n")
	if id != "example" || version != "1.2" {
		t.Fatalf("id=%s version=%s", id, version)
	}
	if cpuModel("processor\t: 0\nmodel name\t: Test CPU\n") != "Test CPU" {
		t.Fatal("cpu model")
	}
	if memTotalBytes("MemTotal:       1024 kB\n") != 1024*1024 {
		t.Fatal("memory total")
	}
	if got := parseVmHWM("Name:\tx\nVmPeak:\t  9000 kB\nVmHWM:\t    2048 kB\nVmRSS:\t 1024 kB\n"); got != 2048*1024 {
		t.Fatalf("VmHWM = %d", got)
	}
	for _, status := range []string{"", "VmHWM:\tlots kB\n", "VmHWM:\t12 MB\n"} {
		if parseVmHWM(status) != 0 {
			t.Fatalf("%q parsed", status)
		}
	}
	if u, err := SampleProcess(); err != nil || u.PeakRSS < u.RSS {
		t.Fatalf("live high-water %d below rss %d (err %v)", u.PeakRSS, u.RSS, err)
	}
	host := CurrentHost()
	if host.Role != hostRole || host.GOOS != "linux" || host.CoreCount < 1 {
		t.Fatalf("host = %#v", host)
	}
	if host.OSVersion == "" || host.CPUModel == "" || host.TotalPhysicalBytes == 0 {
		t.Fatalf("host details = %#v", host)
	}
}
