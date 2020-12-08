package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var reCPUInfo = regexp.MustCompile(`(?m)cpu MHz\s+: (.*)$`)
var reLoadAvg = regexp.MustCompile(`(?m)(.*)+ (.*)+ (.*)+ (\d+)/(\d+) (\d+)`)
var reMemFree = regexp.MustCompile(`(?m)MemFree:\s+(\d+)\s+`)
var reMemTotal = regexp.MustCompile(`(?m)MemTotal:\s+(\d+)\s+`)
var reMemAvailable = regexp.MustCompile(`(?m)MemAvailable:\s+(\d+)\s+`)
var reSwapTotal = regexp.MustCompile(`(?m)SwapTotal:\s+(\d+)\s+`)
var reSwapFree = regexp.MustCompile(`(?m)SwapFree:\s+(\d+)\s+`)
var reBootTime = regexp.MustCompile(`(?m)btime (\d+)`)
var reContextSwitches = regexp.MustCompile(`(?m)ctxt (\d+)`)
var reInterrupts = regexp.MustCompile(`(?m)intr (\d+)`)

type CPUInfo struct {
	AverageFrequenceInHz float64 `json:"average_frequence_in_hz"`
	NumberOfCores        int64   `json:"number_of_cores"`
}

func ParseCpuInfo(c Config) (*CPUInfo, error) {
	file, err := ioutil.ReadFile(filepath.Join(c.BaseDir, "/proc/cpuinfo"))
	if err != nil {
		return nil, err
	}

	found := reCPUInfo.FindAllSubmatch(file, -1)
	if len(found) == 0 {
		return nil, ErrNoMatch
	}
	sumFreq := 0.0
	countFreq := int64(0)
	for _, match := range found {
		float, err := strconv.ParseFloat(string(match[1]), 64)
		if err != nil {
			return nil, err
		}
		sumFreq += float
		countFreq++
	}

	return &CPUInfo{
		AverageFrequenceInHz: sumFreq / float64(countFreq) * 1e6,
		NumberOfCores:        countFreq,
	}, nil
}

var ErrEmptyHostname = errors.New("empty hostname")

func ParseHostname(c Config) (string, error) {
	file, err := ioutil.ReadFile(filepath.Join(c.BaseDir, "/etc/hostname"))
	if err != nil {
		return "", err
	}

	if len(file) == 0 {
		return "", ErrEmptyHostname
	}

	return strings.TrimSpace(string(file)), nil
}

type LoadAvg struct {
	LA1m             float64 `json:"la_1m"`
	LA5m             float64 `json:"la_5m"`
	LA15m            float64 `json:"la_15m"`
	RunningProcesses int64   `json:"running_processes"`
	TotalProcesses   int64   `json:"total_processes"`
	MaxPID           int64   `json:"max_pid"`
}

var ErrNoMatch = errors.New("no match found")

func ParseLoadAvg(c Config) (*LoadAvg, error) {
	file, err := ioutil.ReadFile(filepath.Join(c.BaseDir, "/proc/loadavg"))
	if err != nil {
		return nil, err
	}

	submatch := reLoadAvg.FindStringSubmatch(string(file))
	if len(submatch) == 0 {
		return nil, ErrNoMatch
	}

	la1m, err := strconv.ParseFloat(submatch[1], 64)
	if err != nil {
		return nil, err
	}
	la5m, err := strconv.ParseFloat(submatch[2], 64)
	if err != nil {
		return nil, err
	}
	la15m, err := strconv.ParseFloat(submatch[3], 64)
	if err != nil {
		return nil, err
	}
	runningProcesses, err := strconv.ParseInt(submatch[4], 10, 64)
	if err != nil {
		return nil, err
	}
	totalProcesses, err := strconv.ParseInt(submatch[5], 10, 64)
	if err != nil {
		return nil, err
	}
	maxPid, err := strconv.ParseInt(submatch[6], 10, 64)
	if err != nil {
		return nil, err
	}

	return &LoadAvg{
		LA1m:             la1m,
		LA5m:             la5m,
		LA15m:            la15m,
		RunningProcesses: runningProcesses,
		TotalProcesses:   totalProcesses,
		MaxPID:           maxPid,
	}, nil
}

type MemInfo struct {
	MemFreeBytes      int64 `json:"mem_free_bytes"`
	MemTotalBytes     int64 `json:"mem_total_bytes"`
	MemAvailableBytes int64 `json:"mem_available_bytes"`

	SwapFreeBytes  int64 `json:"swap_free_bytes"`
	SwapTotalBytes int64 `json:"swap_available_bytes"`
}

func ParseMemInfo(c Config) (*MemInfo, error) {
	file, err := ioutil.ReadFile(filepath.Join(c.BaseDir, "/proc/meminfo"))
	if err != nil {
		return nil, err
	}

	strFile := string(file)
	memFree, err := FindSubmatchInt(reMemFree, strFile)
	if err != nil {
		return nil, err
	}
	memAvail, err := FindSubmatchInt(reMemAvailable, strFile)
	if err != nil {
		return nil, err
	}
	memTotal, err := FindSubmatchInt(reMemTotal, strFile)
	if err != nil {
		return nil, err
	}
	swapFree, err := FindSubmatchInt(reSwapFree, strFile)
	if err != nil {
		return nil, err
	}
	swapTotal, err := FindSubmatchInt(reSwapTotal, strFile)
	if err != nil {
		return nil, err
	}

	return &MemInfo{
		MemFreeBytes:      memFree * 1e3,
		MemTotalBytes:     memTotal * 1e3,
		MemAvailableBytes: memAvail * 1e3,
		SwapFreeBytes:     swapFree * 1e3,
		SwapTotalBytes:    swapTotal * 1e3,
	}, nil
}

func FindSubmatchInt(re *regexp.Regexp, text string) (int64, error) {
	submatch := re.FindStringSubmatch(text)
	if len(submatch) == 0 {
		return 0, ErrNoMatch
	}

	return strconv.ParseInt(submatch[1], 10, 64)
}

type BlockStat struct {
	ReadIOs               int64  `json:"read_ios"`
	ReadBytes             int64  `json:"read_bytes"`
	ReadWaitMilliseconds  int64  `json:"read_wait_milliseconds"`
	WriteIOs              int64  `json:"write_ios"`
	WriteBytes            int64  `json:"write_bytes"`
	WriteWaitMilliseconds int64  `json:"write_milliseconds"`
	Device                string `json:"device"`
}

func ParseBlockStat(c Config, blockDevice string) (*BlockStat, error) {
	file, err := ioutil.ReadFile(fmt.Sprintf(filepath.Join(c.BaseDir, "/sys/block/%s/stat"), blockDevice))
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(file))

	readIOs, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return nil, err
	}
	readSectors, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, err
	}
	readWaitMs, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return nil, err
	}
	writeIOs, err := strconv.ParseInt(fields[4], 10, 64)
	if err != nil {
		return nil, err
	}
	writeSectors, err := strconv.ParseInt(fields[6], 10, 64)
	if err != nil {
		return nil, err
	}
	writeWaitMs, err := strconv.ParseInt(fields[7], 10, 64)
	if err != nil {
		return nil, err
	}

	return &BlockStat{
		ReadIOs:               readIOs,
		ReadBytes:             readSectors * 512, // each sector exactly 512 bytes each
		ReadWaitMilliseconds:  readWaitMs,
		WriteIOs:              writeIOs,
		WriteBytes:            writeSectors * 512,
		WriteWaitMilliseconds: writeWaitMs,
		Device:                blockDevice,
	}, nil
}

type ProcStat struct {
	UserMilliseconds    int64 `json:"user_milliseconds"`
	NiceMilliseconds    int64 `json:"nice_milliseconds"`
	SystemMilliseconds  int64 `json:"system_milliseconds"`
	IdleMilliseconds    int64 `json:"idle_milliseconds"`
	IOWaitMilliseconds  int64 `json:"io_wait_milliseconds"`
	IRQMilliseconds     int64 `json:"irq_milliseconds"`
	SoftIRQMilliseconds int64 `json:"soft_irq_milliseconds"`
	BootTime            int64 `json:"boot_time"`
	Interrupts          int64 `json:"interrupts"`
	ContextSwitches     int64 `json:"context_switches"`
}

func ParseProcStat(c Config) (*ProcStat, error) {
	file, err := ioutil.ReadFile(filepath.Join(c.BaseDir, "/proc/stat"))
	if err != nil {
		return nil, err
	}
	fileStr := string(file)
	splitted := strings.Split(fileStr, "\n")
	if len(splitted) == 0 {
		return nil, ErrNoMatch
	}

	fields := strings.Fields(splitted[0])
	user, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return nil, err
	}
	nice, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, err
	}
	system, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return nil, err
	}
	idle, err := strconv.ParseInt(fields[4], 10, 64)
	if err != nil {
		return nil, err
	}
	iowait, err := strconv.ParseInt(fields[5], 10, 64)
	if err != nil {
		return nil, err
	}
	irq, err := strconv.ParseInt(fields[6], 10, 64)
	if err != nil {
		return nil, err
	}
	softirq, err := strconv.ParseInt(fields[7], 10, 64)
	if err != nil {
		return nil, err
	}
	bootTime, err := FindSubmatchInt(reBootTime, string(file))
	if err != nil {
		return nil, err
	}
	ctxt, err := FindSubmatchInt(reContextSwitches, string(file))
	if err != nil {
		return nil, err
	}
	intr, err := FindSubmatchInt(reInterrupts, string(file))
	if err != nil {
		return nil, err
	}
	return &ProcStat{
		UserMilliseconds:    user / 10, // (milliseconds in second) / CLK_TCK (default 100) = 10
		NiceMilliseconds:    nice / 10,
		SystemMilliseconds:  system / 10,
		IdleMilliseconds:    idle / 10,
		IOWaitMilliseconds:  iowait / 10,
		IRQMilliseconds:     irq / 10,
		SoftIRQMilliseconds: softirq / 10,
		BootTime:            bootTime,
		Interrupts:          intr,
		ContextSwitches:     ctxt,
	}, nil
}

type NetDev struct {
	Iface         string `json:"iface"`
	ReceivedBytes int64  `json:"received_bytes"`
	SentBytes     int64  `json:"sent_bytes"`
}

func ParseNetDev(c Config) ([]NetDev, error) {
	if !c.EnableNetworkMonitoring {
		return nil, nil
	}
	file, err := ioutil.ReadFile(filepath.Join(c.BaseDir, "/proc/net/dev"))
	if err != nil {
		return nil, err
	}
	fileStr := string(file)
	netDevs := make([]NetDev, 0)
	for _, iface := range strings.Split(c.Ifaces, ",") {
		iface := strings.TrimSpace(iface)
		reIface := regexp.MustCompile(fmt.Sprintf("%s:(.*)", iface))
		submatch := reIface.FindStringSubmatch(fileStr)
		if len(submatch) == 0 {
			return nil, ErrNoMatch
		}

		fields := strings.Fields(submatch[1])
		var netDev NetDev
		rxBytes, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return nil, err
		}
		txBytes, err := strconv.ParseInt(fields[8], 10, 64)
		if err != nil {
			return nil, err
		}

		netDev.ReceivedBytes = rxBytes
		netDev.SentBytes = txBytes
		netDev.Iface = iface
		netDevs = append(netDevs, netDev)
	}

	return netDevs, nil
}

func LocalPrinter(c Config) {
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			info, err := ParseCpuInfo(c)
			if err != nil {
				log.Panicf("failed to parse cpu info: %s", err)
			}
			hostname, err := ParseHostname(c)
			if err != nil {
				log.Panicf("failed to parse hostname: %s", err)
			}
			la, err := ParseLoadAvg(c)
			if err != nil {
				log.Panicf("failed to parse LA: %s", err)
			}
			memInfo, err := ParseMemInfo(c)
			if err != nil {
				log.Panicf("failed to parse meminfo: %s", err)
			}
			blockStats := make([]BlockStat, 0)
			for _, blockDevice := range strings.Split(c.Disks, ",") {
				stat, err := ParseBlockStat(c, blockDevice)
				if err != nil {
					log.Panicf("failed to parse block device %s: %s", blockDevice, err)
				}
				blockStats = append(blockStats, *stat)
			}

			procStat, err := ParseProcStat(c)
			if err != nil {
				log.Panicf("failed to parse proc stat: %s", err)
			}
			netDevs, err := ParseNetDev(c)
			if err != nil {
				log.Panicf("failed to parse net dev: %s", err)
			}

			log.Printf("Average Freq: %.2f MHz, %d cores", info.AverageFrequenceInHz/1e6, info.NumberOfCores)
			log.Printf("Hostname: %s", hostname)
			log.Printf("Load Average: %.2f %.2f %.2f %d/%d %d", la.LA1m, la.LA5m, la.LA15m, la.RunningProcesses, la.TotalProcesses, la.MaxPID)
			log.Printf("Memory info: RAM: %d/%d MB Free SWAP: %d/%d MB Free", memInfo.MemAvailableBytes/1e6, memInfo.MemTotalBytes/1e6, memInfo.SwapFreeBytes/1e6, memInfo.SwapTotalBytes/1e6)
			log.Println("Disks:")
			for _, stat := range blockStats {
				log.Printf("%s: Reads: %d IO (%d bytes, %dms wait), Writes:%d IO (%d bytes, %dms wait)", stat.Device, stat.ReadIOs, stat.ReadBytes, stat.ReadWaitMilliseconds, stat.WriteIOs, stat.WriteBytes, stat.WriteWaitMilliseconds)
			}

			log.Printf("Proc stat: %.2f%% idle", float64(procStat.IdleMilliseconds*100)/float64(procStat.UserMilliseconds+procStat.NiceMilliseconds+procStat.SystemMilliseconds+procStat.IdleMilliseconds+procStat.IOWaitMilliseconds+procStat.IRQMilliseconds+procStat.SoftIRQMilliseconds))
			log.Printf("Boot time: %d, interrupts: %d, context switches: %d", procStat.BootTime, procStat.Interrupts, procStat.ContextSwitches)
			for _, dev := range netDevs {
				log.Printf("%s: %dMB received, %dMB sent", dev.Iface, dev.ReceivedBytes/1e6, dev.SentBytes/1e6)
			}
		}
	}
}

type Config struct {
	BaseDir                 string `long:"base_dir" env:"BASE_DIR" default:""`
	Ifaces                  string `long:"ifaces" env:"IFACES" default:"enp3s0"`
	Disks                   string `long:"disks" env:"DISKS" default:"sda,sdb,sdc"`
	ListenAddr              string `long:"listen_addr" env:"LISTEN_ADDR" default:"localhost:33333"`
	EnableNetworkMonitoring bool   `long:"enable_network_monitoring" env:"ENABLE_NETWORK_MONITORING"`
	Local                   bool   `long:"local" env:"LOCAL"`
	IntervalMilliseconds    int64  `long:"interval_milliseconds" env:"INTERVAL_MILLISECONDS" default:"250"`
	BasicAuthUser           string `long:"basic_auth_user" env:"BASIC_AUTH_USER" default:""`
	BasicAuthPassword       string `long:"basic_auth_password" env:"BASIC_AUTH_PASSWORD" default:""`
	PIDFile                 string `long:"pid_file" env:"PID_FILE" default:"./metrics-collector.pid"`
}

func main() {
	var config Config
	_, err := flags.Parse(&config)
	if err != nil {
		log.Fatalf("failed to parse flags: %s", err)
	}

	err = ioutil.WriteFile(config.PIDFile, []byte(strconv.Itoa(os.Getpid())), os.ModePerm)
	if err != nil {
		log.Panicf("failed to write pid file: %s", err)
	}

	if config.Local {
		LocalPrinter(config)
	} else {
		PrometheusExporter(config)
	}
}

func PrometheusExporter(config Config) {
	hostname, err := ParseHostname(config)
	if err != nil {
		log.Panicf("failed to parse hostname: %s", err)
	}

	cpuFreqGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "metrics_collector_cpu_average_frequency_hz",
		Help:        "CPU Average Frequence in Hertz",
		ConstLabels: prometheus.Labels{"hostname": hostname},
	})

	coreCountGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "metrics_collector_core_count",
		Help:        "Number of cores",
		ConstLabels: prometheus.Labels{"hostname": hostname},
	})

	laGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:        "metrics_collector_load_average",
		Help:        "Load average statistics",
		ConstLabels: prometheus.Labels{"hostname": hostname},
	}, []string{"la_type"})

	memoryGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:        "metrics_collector_memory_bytes",
		Help:        "Memory and Swap statistics in bytes",
		ConstLabels: prometheus.Labels{"hostname": hostname},
	}, []string{"memory_type"})

	diskIOGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:        "metrics_collector_disk_io",
		Help:        "Disk IO statistics",
		ConstLabels: prometheus.Labels{"hostname": hostname},
	}, []string{"disk_name", "operation_type"})

	diskBytesGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:        "metrics_collector_disk_bytes",
		Help:        "Disk bytes statistics",
		ConstLabels: prometheus.Labels{"hostname": hostname},
	}, []string{"disk_name", "operation_type"})

	diskWaitGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:        "metrics_collector_disk_wait_ms",
		Help:        "Disk wait statistics",
		ConstLabels: prometheus.Labels{"hostname": hostname},
	}, []string{"disk_name", "operation_type"})

	cpuUsageGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:        "metrics_collector_cpu_usage_ms",
		Help:        "CPU Usage in ms",
		ConstLabels: prometheus.Labels{"hostname": hostname},
	}, []string{"usage_type"})
	cpuInterrupts := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "metrics_collector_cpu_interrupts",
		Help:        "CPU interrupts count",
		ConstLabels: prometheus.Labels{"hostname": hostname},
	})
	cpuContextSwitches := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "metrics_collector_cpu_context_switches",
		Help:        "CPU context switches count",
		ConstLabels: prometheus.Labels{"hostname": hostname},
	})
	bootTimeGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "metrics_collector_boot_time",
		Help:        "Host boot time",
		ConstLabels: prometheus.Labels{"hostname": hostname},
	})

	netBytesGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:        "metrics_collector_net_bytes",
		Help:        "Network statistics in bytes",
		ConstLabels: prometheus.Labels{"hostname": hostname},
	}, []string{"iface", "operation_type"})

	prometheus.MustRegister(cpuFreqGauge, coreCountGauge, laGauge, memoryGauge,
		diskIOGauge, diskWaitGauge, diskBytesGauge, cpuUsageGauge, cpuInterrupts, cpuContextSwitches,
		bootTimeGauge, netBytesGauge)

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if config.BasicAuthUser != "" && config.BasicAuthPassword != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != config.BasicAuthUser || pass != config.BasicAuthPassword {
				w.WriteHeader(500)
				return
			}
		}

		promhttp.Handler().ServeHTTP(w, r)
	})
	prometheus.Unregister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	prometheus.Unregister(prometheus.NewGoCollector())

	go func() {
		log.Printf("Starting prometheus metrics server on %s", config.ListenAddr)
		log.Fatal(http.ListenAndServe(config.ListenAddr, nil))
	}()
	for {
		ci, err := ParseCpuInfo(config)
		if err != nil {
			log.Panicf("failed to parse cpu info: %s", err)
		}

		coreCountGauge.Set(float64(ci.NumberOfCores))
		cpuFreqGauge.Set(ci.AverageFrequenceInHz)
		la, err := ParseLoadAvg(config)
		if err != nil {
			log.Panicf("failed to parse la: %s", err)
		}

		laGauge.WithLabelValues("1m").Set(la.LA1m)
		laGauge.WithLabelValues("5m").Set(la.LA5m)
		laGauge.WithLabelValues("15m").Set(la.LA15m)
		laGauge.WithLabelValues("running_processes").Set(float64(la.RunningProcesses))
		laGauge.WithLabelValues("total_processes").Set(float64(la.TotalProcesses))
		laGauge.WithLabelValues("max_pid").Set(float64(la.MaxPID))

		mi, err := ParseMemInfo(config)
		if err != nil {
			log.Panicf("failed to parse meminfo: %s", err)
		}

		memoryGauge.WithLabelValues("swap_free").Set(float64(mi.SwapFreeBytes))
		memoryGauge.WithLabelValues("swap_total").Set(float64(mi.SwapTotalBytes))
		memoryGauge.WithLabelValues("ram_free").Set(float64(mi.MemFreeBytes))
		memoryGauge.WithLabelValues("ram_total").Set(float64(mi.MemTotalBytes))
		memoryGauge.WithLabelValues("ram_available").Set(float64(mi.MemAvailableBytes))

		for _, blockDevice := range strings.Split(config.Disks, ",") {
			stat, err := ParseBlockStat(config, blockDevice)
			if err != nil {
				log.Panicf("failed to parse block device %s: %s", blockDevice, err)
			}

			diskIOGauge.WithLabelValues(stat.Device, "write").Set(float64(stat.WriteIOs))
			diskIOGauge.WithLabelValues(stat.Device, "read").Set(float64(stat.ReadIOs))

			diskBytesGauge.WithLabelValues(stat.Device, "write").Set(float64(stat.WriteBytes))
			diskBytesGauge.WithLabelValues(stat.Device, "read").Set(float64(stat.ReadBytes))

			diskWaitGauge.WithLabelValues(stat.Device, "write").Set(float64(stat.WriteWaitMilliseconds))
			diskWaitGauge.WithLabelValues(stat.Device, "read").Set(float64(stat.ReadWaitMilliseconds))
		}

		procStats, err := ParseProcStat(config)
		if err != nil {
			log.Panicf("failed to parse proc stat: %s", err)
		}

		bootTimeGauge.Set(float64(procStats.BootTime))
		cpuUsageGauge.WithLabelValues("user").Set(float64(procStats.UserMilliseconds))
		cpuUsageGauge.WithLabelValues("nice").Set(float64(procStats.NiceMilliseconds))
		cpuUsageGauge.WithLabelValues("system").Set(float64(procStats.SystemMilliseconds))
		cpuUsageGauge.WithLabelValues("idle").Set(float64(procStats.IdleMilliseconds))
		cpuUsageGauge.WithLabelValues("iowait").Set(float64(procStats.IOWaitMilliseconds))
		cpuUsageGauge.WithLabelValues("softirq").Set(float64(procStats.SoftIRQMilliseconds))
		cpuInterrupts.Set(float64(procStats.Interrupts))
		cpuContextSwitches.Set(float64(procStats.ContextSwitches))

		netDevs, err := ParseNetDev(config)
		if err != nil {
			log.Panicf("failed to parse net dev: %s", err)
		}

		for _, dev := range netDevs {
			netBytesGauge.WithLabelValues(dev.Iface, "sent").Set(float64(dev.SentBytes))
			netBytesGauge.WithLabelValues(dev.Iface, "received").Set(float64(dev.ReceivedBytes))
		}

		time.Sleep(time.Duration(config.IntervalMilliseconds) * time.Millisecond)
	}
}
