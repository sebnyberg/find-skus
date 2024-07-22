package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/gosuri/uitable"
)

var (
	regionType                    = flag.String("region-type", "Physical", "Filter by region type, allowed values: [Physical, Logical, All], default: Physical")
	regionCategory                = flag.String("region-category", RegionCategoryUndefined, "If set, filter by region category, allowed values: [Recommended, Other]")
	downloadParallelism           = flag.Uint64("download-parallelism", 12, "Number of parallel downloads")
	tempDir                       = flag.String("temp-dir", "", "Directory to download skus")
	memory                        = flag.Uint64("memory", 0, "Memory in GB")
	memoryMin                     = flag.Uint64("memory-min", 0, "Minimum memory in GB")
	memoryMax                     = flag.Uint64("memory-max", 0, "Maximum memory in GB")
	cpu                           = flag.Uint64("cpu", 0, "vCPUs")
	cpuMin                        = flag.Uint64("cpu-min", 0, "Minimum vCPUs")
	cpuMax                        = flag.Uint64("cpu-max", 0, "Maximum vCPUs")
	locationSummary               = flag.Bool("by-location", false, "Whether to summarize by location")
	vCPUsPerCore                  = flag.Uint64("vcpus-per-core", 0, "Require exact vCPUs per core")
	mustHaveAZ                    = flag.Bool("must-have-az", false, "Whether availability zones are required")
	mustHavePremiumIO             = flag.Bool("premium-io", false, "SKU must have premium IO")
	mustHaveEphemeralDisk         = flag.Bool("ephemeral-disk", false, "SKU must have ephemeral disk")
	mustHaveEncryptionAtHost      = flag.Bool("encryption-at-host", false, "SKU must have encryption at host")
	mustHaveAcceleratedNetworking = flag.Bool("accelerated-networking", false, "SKU must have accelerated networking")
	mustBeAvailable               = flag.Bool("must-be-available", false, "SKU must be available, i.e. not restricted")
	maxZoneDegredation            = flag.Uint64("max-zone-degredation", 0, "Maximum unavailable zones allowed")
	verbose                       = flag.Bool("v", false, "Whether to log verbose output")
	quiet                         = flag.Bool("q", false, "Whether to quiet all logs")
	output                        = flag.String("o", "table", "Output type [table, json], default: json")
	sortBy                        = flag.String("sort-by", "name", "Sort by [name], default: name")
	sizeRegexpStr                 = flag.String("size", ".*", "Size regexp, default: .*")
	familyRegexpStr               = flag.String("family", ".*", "Family regexp, default: .*")
	zonesMin                      = flag.Uint64("zones-min", 0, "Minimum SKU AZs")
	locationsKeepList             = flag.String("l", "", "Comma separated list (no spaces) of locations to keep, e.g. 'eastus,westus'")
	redownload                    = flag.Bool("redownload", false, "Whether to re-download data")
)

const (
	Version = "0.1.0"

	RegionTypePhysical = "Physical"
	RegionTypeLogical  = "Logical"
	RegionTypeAll      = "All"

	RegionCategoryRecommended = "Recommended"
	RegionCategoryUndefined   = ""
	RegionCategoryOther       = "Other"

	resourceTypeVirtualMachines = "virtualMachines"
)

func validateRegexp(s string) error {
	_, err := regexp.Compile(s)
	return err
}

type skuFilter struct {
	memoryMin             uint64
	memoryMax             uint64
	cpuMin                uint64
	cpuMax                uint64
	premiumIO             bool
	ephemeralDisk         bool
	vCPUsPerCore          uint64
	familyRegexp          *regexp.Regexp
	sizeRegexp            *regexp.Regexp
	encryptionAtHost      bool
	acceleratedNetworking bool
	resourceType          string
	minZones              uint64
	maxZoneDegredation    uint64
	mustBeAvailable       bool
}

func (f skuFilter) Match(sku JsonSku) (bool, error) {
	if sku.ResourceType != f.resourceType {
		return false, nil
	}
	if !f.familyRegexp.MatchString(sku.Family) {
		return false, nil
	}
	if !f.sizeRegexp.MatchString(sku.Size) {
		return false, nil
	}
	if sku.Memory() < f.memoryMin || sku.Memory() > f.memoryMax {
		return false, nil
	}
	if sku.VCPUs() < f.cpuMin || sku.VCPUs() > f.cpuMax {
		return false, nil
	}
	if f.vCPUsPerCore > 0 && sku.VCPUsPerCore() != f.vCPUsPerCore {
		return false, nil
	}
	if f.encryptionAtHost && sku.GetCapability("EncryptionAtHostSupported") != "True" {
		return false, nil
	}
	if f.ephemeralDisk && sku.GetCapability("EphemeralOSDiskSupported") != "True" {
		return false, nil
	}
	if f.premiumIO && sku.GetCapability("PremiumIO") != "True" {
		return false, nil
	}
	if f.acceleratedNetworking && sku.GetCapability("AcceleratedNetworkingEnabled") != "True" {
		return false, nil
	}
	if f.resourceType != "" && sku.ResourceType != f.resourceType {
		return false, nil
	}
	if f.minZones > 0 && len(sku.LocationInfo) > 0 {
		if len(sku.LocationInfo[0].Zones) < int(f.minZones) {
			return false, nil
		}
	}
	if f.mustBeAvailable {
		if !sku.IsAvailable(f.maxZoneDegredation) {
			return false, nil
		}
	}
	return true, nil
}

type JsonSku struct {
	ApiVersions  []string           `json:"apiVersions"`
	Capabilities []JsonCapability   `json:"capabilities"`
	Capacity     interface{}        `json:"capacity"`
	Costs        interface{}        `json:"costs"`
	Family       string             `json:"family"`
	Kind         interface{}        `json:"kind"`
	LocationInfo []JsonLocationInfo `json:"locationInfo"`
	Locations    []string           `json:"locations"`
	Name         string             `json:"name"`
	ResourceType string             `json:"resourceType"`
	Restrictions []JsonRestriction  `json:"restrictions"`
	Size         string             `json:"size"`
	Tier         string             `json:"tier"`
}

func (s JsonSku) GetCapability(name string) string {
	for _, c := range s.Capabilities {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}
func (s JsonSku) Memory() uint64 {
	cap := s.GetCapability("MemoryGB")
	v, err := strconv.ParseUint(cap, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
func (s JsonSku) VCPUs() uint64 {
	cap := s.GetCapability("vCPUs")
	v, err := strconv.ParseUint(cap, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
func (s JsonSku) VCPUsPerCore() uint64 {
	cap := s.GetCapability("vCPUsPerCore")
	v, err := strconv.ParseUint(cap, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
func (s JsonSku) IsAvailable(maxZoneDegredation uint64) bool {
	// A sku is considered unavailable if it has any restrictions preventing it
	// from being scheduled for the current subscription
	if len(s.Restrictions) != 0 {
		for _, r := range s.Restrictions {
			if r.ReasonCode == "NotAvailableForSubscription" {
				if len(r.RestrictionInfo.Zones) > int(maxZoneDegredation) {
					return false
				}
			}
		}
	}
	return true
}

type JsonRestriction struct {
	ReasonCode      string              `json:"reasonCode"`
	RestrictionInfo JsonRestrictionInfo `json:"restrictionInfo"`
	Type            string              `json:"type"`
	Values          []string            `json:"values"`
}

type JsonRestrictionInfo struct {
	Locations []string `json:"locations"`
	Zones     []string `json:"zones"`
}

type JsonCapability struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type JsonLocationInfo struct {
	Location    string            `json:"location"`
	ZoneDetails []JsonZoneDetails `json:"zoneDetails"`
	Zones       []string          `json:"zones"`
}

type JsonZoneDetails struct {
	Name         []string         `json:"Name"`
	Name2        []interface{}    `json:"name"`
	Capabilities []JsonCapability `json:"capabilities"`
}

type Result struct {
	Location              string `json:"location"`
	Name                  string `json:"name"`
	Size                  string `json:"size"`
	VCPUs                 uint64 `json:"vCPUs"`
	VCPUsPerCore          uint64 `json:"vCPUsPerCore"`
	MemoryGB              uint64 `json:"memoryGB"`
	CpuArchitectureType   string `json:"cpuArch"`
	PremiumIO             bool   `json:"premiumIO"`
	EphemeralDisk         bool   `json:"ephemeralDisk"`
	EncryptionAtHost      bool   `json:"encryptionAtHost"`
	AcceleratedNetworking bool   `json:"acceleratedNetworking"`
	Available             bool   `json:"available"`
}

func (r Result) WriteHeader(t *uitable.Table) {
	t.AddRow("Location", "Name", "Size", "VCPUs", "VCPUsPerCore", "MemoryGB", "CpuArch", "PremiumIO", "EphemeralDisk", "EncryptionAtHost", "AcceleratedNetworking", "Available")
}
func (r Result) WriteTo(t *uitable.Table) {
	t.AddRow(r.Location, r.Name, r.Size, r.VCPUs, r.VCPUsPerCore, r.MemoryGB, r.CpuArchitectureType, r.PremiumIO, r.EphemeralDisk, r.EncryptionAtHost, r.AcceleratedNetworking, r.Available)
}

type ResultByLocation struct {
	Name              string `json:"name"`
	RegionCategory    string `json:"regionCategory"`
	AZCount           uint64 `json:"azCount"`
	SKUCount          uint64 `json:"skuCount"`
	SKUCountAvailable uint64 `json:"skuCountAvailable"`
}

func (r ResultByLocation) WriteHeader(t *uitable.Table) {
	t.AddRow("Name", "RegionCategory", "AZCount", "SKUCount", "SKUCountAvailable")
}
func (r ResultByLocation) WriteTo(t *uitable.Table) {
	t.AddRow(r.Name, r.RegionCategory, r.AZCount, r.SKUCount, r.SKUCountAvailable)
}

// maybeDownload downloads a file before parsing into res, if:
//
// - the downloadPath does not already contain a file, or
// - the file is empty, or
// - the file could not already be parsed into res
func maybeDownload[T any](
	downloadPath string,
	trunc bool,
	cmd *exec.Cmd,
	res T,
) (retErr error) {
	flags := os.O_CREATE | os.O_RDWR
	if trunc {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(downloadPath, flags, 0644)
	defer func() {
		if closeErr := f.Close(); closeErr != nil && retErr == nil {
			retErr = closeErr
		}
	}()
	if err != nil {
		return fmt.Errorf("failed to open file %v, %w", downloadPath, err)
	}

	// Fast-path
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file %v, %w", downloadPath, err)
	}
	if fi.Size() > 0 {
		// Seems like file already exists, try to parse
		var testParse T
		if err := json.NewDecoder(f).Decode(&testParse); err == nil {
			// Reset file position
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("seek file %v, %w", downloadPath, err)
			}
			if err = json.NewDecoder(f).Decode(res); err != nil {
				return fmt.Errorf("unexpected error decoding %v, %w", downloadPath, err)
			}
			return nil
		}

		// Parsing failed, assume that the file is corrupt and re-download
		slog.Warn("file exists but pailed to parse, re-downloading",
			slog.String("downloadPath", downloadPath),
		)

		// Truncate
		if err := f.Truncate(0); err != nil {
			return fmt.Errorf("failed to truncate file %v, %w", downloadPath, err)
		}
	}

	// Download
	slog.Info("Downloading...", slog.String("downloadPath", downloadPath))
	cmd.Stdout = f
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run cmd, %w", err)
	}

	// Seek
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("seek file %v, %w", downloadPath, err)
	}

	// Parse
	if err := json.NewDecoder(f).Decode(&res); err != nil {
		return fmt.Errorf("decode json, %w", err)
	}
	return nil
}

func getSkusForLocation(location, downloadDir string, doTruncate bool) ([]JsonSku, error) {
	cmd := exec.Command("az", "vm", "list-skus", "-l", location)
	downloadPath := path.Join(downloadDir, location+".json")
	var res []JsonSku
	err := maybeDownload(downloadPath, doTruncate, cmd, &res)
	if err != nil {
		return nil, fmt.Errorf("sku download, %w", err)
	}
	return res, nil
}

func getSkus(locations []JsonLocation, parallelism uint64, downloadDir string) (map[string][]JsonSku, error) {
	var wg sync.WaitGroup
	slog.Info("Initializing download / cache check",
		slog.Uint64("parallelism", parallelism),
	)
	var batchch = make(chan struct{}, parallelism)
	m := make(map[string][]JsonSku)
	var mtx sync.Mutex
	var firstError error
	var errOnce sync.Once
	for _, l := range locations {
		wg.Add(1)
		batchch <- struct{}{}
		go func(location string) {
			defer wg.Done()
			defer func() { <-batchch }()
			res, err := getSkusForLocation(location, downloadDir, *redownload)
			if err != nil {
				errOnce.Do(func() {
					firstError = fmt.Errorf("download for %v failed, %w", location, err)
				})
				return
			}
			mtx.Lock()
			m[location] = res
			mtx.Unlock()
		}(l.Name)
	}
	wg.Wait()
	return m, firstError
}

func getLocations(downloadDir string, doTruncate bool) ([]JsonLocation, error) {
	downloadPath := path.Join(downloadDir, "locations.json")
	var locations []JsonLocation
	cmd := exec.Command("az", "account", "list-locations", "-o", "json")
	err := maybeDownload(downloadPath, doTruncate, cmd, &locations)
	if err != nil {
		return nil, fmt.Errorf("location download failed, %w", err)
	}
	return locations, nil
}

type locationFilter struct {
	regionType     string
	regionCategory string
	mustHaveAZ     bool
	minZones       uint64
	keepLocations  map[string]struct{}
}

func (f locationFilter) Match(l JsonLocation) bool {
	if f.regionType != RegionTypeAll && l.Metadata.RegionType != f.regionType {
		return false
	}
	if f.regionCategory != "" && l.Metadata.RegionCategory != f.regionCategory {
		return false
	}
	if f.mustHaveAZ && len(l.AvailabilityZoneMappings) == 0 {
		return false
	}
	if f.minZones > 0 && uint64(len(l.AvailabilityZoneMappings)) < f.minZones {
		return false
	}
	if len(f.keepLocations) != 0 {
		if _, ok := f.keepLocations[l.Name]; !ok {
			return false
		}
	}
	return true
}

type JsonLocation struct {
	AvailabilityZoneMappings []JsonAvailabilityZoneMapping `json:"availabilityZoneMappings"`
	DisplayName              string                        `json:"displayName"`
	ID                       string                        `json:"id"`
	Name                     string                        `json:"name"`
	RegionalDisplayName      string                        `json:"regionalDisplayName"`
	Type                     string                        `json:"type"`
	Metadata                 JsonMetadata                  `json:"metadata"`
}

type JsonMetadata struct {
	Geography        string             `json:"geography"`
	GeographyGroup   string             `json:"geographyGroup"`
	Latitude         string             `json:"latitude"`
	Longitude        string             `json:"longitude"`
	PairedRegion     []JsonPairedRegion `json:"pairedRegion"`
	PhysicalLocation string             `json:"physicalLocation"`
	RegionCategory   string             `json:"regionCategory"`
	RegionType       string             `json:"regionType"`
}

type JsonPairedRegion struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type JsonAvailabilityZoneMapping struct {
	LogicalZone  string `json:"logicalZone"`
	PhysicalZone string `json:"physicalZone"`
}

func validateFlags() error {
	// Memory
	if *memory != 0 {
		if *memoryMin != 0 || *memoryMax != 0 {
			return errors.New("please specify either memory or minMemory and maxMemory, not both")
		}
		*memoryMin = *memory
		*memoryMax = *memory
	} else {
		if *memoryMax < *memoryMin || *memoryMax == 0 {
			*memoryMax = math.MaxUint64
		}
		if *memoryMin > *memoryMax {
			return fmt.Errorf(
				"minMemory (%v) must be smaller or equal to maxMemory (%v)",
				*memoryMin, *memoryMax,
			)
		}
	}

	// CPU
	if *cpu != 0 {
		if *cpuMin != 0 || *cpuMax != 0 {
			return errors.New("please specify either cpu or minCPU and maxCPU, not both")
		}
		*cpuMin = *cpu
		*cpuMax = *cpu
	} else {
		if *cpuMax < *cpuMin || *cpuMax == 0 {
			*cpuMax = math.MaxUint64
		}
		if *cpuMin > *cpuMax {
			return fmt.Errorf(
				"minCPU (%v) must be smaller or equal to maxCPU (%v)",
				*cpuMin, *cpuMax,
			)
		}
	}

	// Output
	if *output == "" {
		*output = "json"
	}
	if strings.ToLower(*output) != "json" && strings.ToLower(*output) != "table" {
		return fmt.Errorf("output must be either 'json' or 'table', got: %v", *output)
	}
	*output = strings.ToLower(*output)

	// RegionType
	if *regionType != RegionTypeAll &&
		*regionType != RegionTypePhysical &&
		*regionType != RegionTypeLogical {
		return fmt.Errorf("regionType must be one of [Physical, Logical], got: %v", *regionType)
	}
	if *regionCategory != RegionCategoryUndefined &&
		*regionCategory != RegionCategoryRecommended &&
		*regionCategory != RegionCategoryOther {
		return fmt.Errorf("regionCategory must be one of [Recommended, Other], got: %v", *regionCategory)
	}

	// Regexpes
	if err := validateRegexp(*sizeRegexpStr); err != nil {
		return fmt.Errorf("size regexp invalid, %w", err)
	}
	if err := validateRegexp(*familyRegexpStr); err != nil {
		return fmt.Errorf("family regexp invalid, %w", err)
	}

	// SortBy
	if *sortBy == "" {
		*sortBy = "name"
	}
	if *sortBy != "name" && *sortBy != "skuCount" {
		return fmt.Errorf("sortBy must be one of [name, skuCount], got: %v", *sortBy)
	}
	return nil
}

func calculateResultByLocation(l JsonLocation, skus []JsonSku, filter skuFilter) (ResultByLocation, error) {
	withUnavailable := filter
	withUnavailable.mustBeAvailable = false
	withUnavailable.maxZoneDegredation = 3 // make super-duper sure we don't filter

	withoutUnavailable := filter
	withoutUnavailable.mustBeAvailable = true

	var count int
	var availableCount int
	for _, s := range skus {
		didMatch, err := withUnavailable.Match(s)
		if err != nil {
			return ResultByLocation{}, err
		}
		if didMatch {
			count++
		}
		didMatch, err = withoutUnavailable.Match(s)
		if err != nil {
			return ResultByLocation{}, err
		}
		if didMatch {
			availableCount++
		}
	}
	res := ResultByLocation{
		Name:              l.Name,
		RegionCategory:    l.Metadata.RegionCategory,
		AZCount:           uint64(len(l.AvailabilityZoneMappings)),
		SKUCount:          uint64(count),
		SKUCountAvailable: uint64(availableCount),
	}
	return res, nil
}

func run() error {
	if err := validateFlags(); err != nil {
		return err
	}

	// Log setup
	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelInfo)
	} else {
		slog.SetLogLoggerLevel(slog.LevelError)
	}
	if *quiet {
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	logArgs := []any{
		slog.Uint64("download-parallelism", *downloadParallelism),
		slog.String("temp-dir", *tempDir),
	}
	if *regionType != RegionTypePhysical {
		logArgs = append(logArgs, slog.String("regionType", *regionType))
	}
	if *regionCategory != RegionCategoryUndefined {
		logArgs = append(logArgs, slog.String("regionCategory", *regionCategory))
	}
	slog.Info("Starting findskus", logArgs...)

	// Initialize temp dir
	if *tempDir == "" {
		*tempDir = path.Join(os.TempDir(), fmt.Sprintf("findkus-%v", Version))
	}
	if err := os.MkdirAll(*tempDir, 0700); err != nil {
		return fmt.Errorf("failed to create temp dir, "+
			"perhaps manually specify dir with --tmp-dir, err: %w",
			err,
		)
	}

	// List and filter locatioons
	locations, err := getLocations(*tempDir, *redownload)
	if err != nil {
		slog.Error("Failed to get locations", slog.String("err", err.Error()))
		log.Fatalln(err)
	}
	sort.Slice(locations, func(i, j int) bool {
		return locations[i].Name < locations[j].Name
	})
	locFilter := locationFilter{
		regionType:     *regionType,
		regionCategory: *regionCategory,
		mustHaveAZ:     *mustHaveAZ,
		keepLocations:  make(map[string]struct{}),
	}
	for _, l := range strings.Split(*locationsKeepList, ",") {
		if l == "" {
			continue
		}
		locFilter.keepLocations[l] = struct{}{}
	}
	var n int
	for _, r := range locations {
		if !locFilter.Match(r) {
			continue
		}
		locations[n] = r
		n++
	}
	locations = locations[:n]

	// Get skus
	skus, err := getSkus(locations, *downloadParallelism, *tempDir)
	if err != nil {
		return fmt.Errorf("download skus failed, %w", err)
	}
	sizeRegexp, err := regexp.Compile(*sizeRegexpStr)
	if err != nil {
		return fmt.Errorf("failed to compile sku size-regex, %w", err)
	}
	familyRegexp, err := regexp.Compile(*familyRegexpStr)
	if err != nil {
		return fmt.Errorf("failed to compile sku family-regex, %w", err)
	}
	sFilter := skuFilter{
		memoryMin:             *memoryMin,
		memoryMax:             *memoryMax,
		cpuMin:                *cpuMin,
		cpuMax:                *cpuMax,
		vCPUsPerCore:          *vCPUsPerCore,
		premiumIO:             *mustHavePremiumIO,
		ephemeralDisk:         *mustHaveEphemeralDisk,
		encryptionAtHost:      *mustHaveEncryptionAtHost,
		acceleratedNetworking: *mustHaveAcceleratedNetworking,
		mustBeAvailable:       *mustBeAvailable,
		resourceType:          resourceTypeVirtualMachines,
		sizeRegexp:            sizeRegexp,
		familyRegexp:          familyRegexp,
		minZones:              *zonesMin,
		maxZoneDegredation:    *maxZoneDegredation,
	}
	type tableable interface {
		WriteHeader(t *uitable.Table)
		WriteTo(t *uitable.Table)
	}
	var results []tableable
	table := uitable.New()

	if *locationSummary {
		var headerWriter ResultByLocation
		headerWriter.WriteHeader(table)
		for _, l := range locations {
			rl, err := calculateResultByLocation(l, skus[l.Name], sFilter)
			if err != nil {
				slog.Error("failed to calculate result by location",
					slog.Any("location", l),
				)
				return fmt.Errorf("failed to calculate result by location %v, %w", l, err)
			}
			results = append(results, rl)
		}
	} else { // Do not roll up by location
		var headerWriter Result
		headerWriter.WriteHeader(table)
		for _, l := range locations {
			for _, sku := range skus[l.Name] {
				didMatch, err := sFilter.Match(sku)
				if err != nil {
					slog.Error("failed to match sku",
						slog.Any("location", l),
					)
					return fmt.Errorf("failed to match sku for location %v, sku %v, %w", l.Name, sku.Name, err)
				}
				if !didMatch {
					continue
				}
				x := Result{
					Location:              l.Name,
					Name:                  sku.Name,
					Size:                  sku.Size,
					VCPUs:                 sku.VCPUs(),
					VCPUsPerCore:          sku.VCPUsPerCore(),
					MemoryGB:              sku.Memory(),
					CpuArchitectureType:   sku.GetCapability("CpuArchitectureType"),
					PremiumIO:             sku.GetCapability("PremiumIO") == "True",
					EphemeralDisk:         sku.GetCapability("EphemeralOSDiskSupported") == "True",
					EncryptionAtHost:      sku.GetCapability("EncryptionAtHostSupported") == "True",
					AcceleratedNetworking: sku.GetCapability("AcceleratedNetworkingEnabled") == "True",
					Available:             sku.IsAvailable(sFilter.maxZoneDegredation),
				}
				results = append(results, x)
			}
		}
	}

	switch *output {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		if err = enc.Encode(results); err != nil {
			return err
		}
	case "table":
		for _, r := range results {
			r.WriteTo(table)
		}
		fmt.Println(table)
	default:
		panic(*output)
	}

	return nil
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatalln(err)
	}
}
