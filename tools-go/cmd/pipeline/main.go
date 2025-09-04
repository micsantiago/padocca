// PADOCCA Pipeline Executor - Declarative attack orchestration
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/padocca/tools/pkg/cache"
	"github.com/padocca/tools/pkg/stealth"
	"github.com/spf13/cobra"
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v3"
)

// Pipeline represents the complete pipeline configuration
type Pipeline struct {
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	Author      string                 `yaml:"author"`
	Version     string                 `yaml:"version"`
	Settings    PipelineSettings       `yaml:"settings"`
	Stages      []Stage                `yaml:"stages"`
	Conditions  []Condition            `yaml:"conditions"`
	OnError     []Action               `yaml:"on_error"`
	OnSuccess   []Action               `yaml:"on_success"`
	
	// Runtime
	results       map[string]interface{}
	cache         *cache.CacheManager
	stealthMgr    *stealth.StealthManager
	mutex         sync.RWMutex
	startTime     time.Time
	endTime       time.Time
}

// PipelineSettings contains global settings
type PipelineSettings struct {
	Cache    CacheSettings    `yaml:"cache"`
	Stealth  StealthSettings  `yaml:"stealth"`
	Parallel ParallelSettings `yaml:"parallel"`
	Output   OutputSettings   `yaml:"output"`
}

// Stage represents a pipeline stage
type Stage struct {
	Name            string   `yaml:"name"`
	Description     string   `yaml:"description"`
	Parallel        bool     `yaml:"parallel"`
	DependsOn       []string `yaml:"depends_on"`
	ManualApproval  bool     `yaml:"manual_approval"`
	Steps           []Step   `yaml:"steps"`
}

// Step represents a single step in a stage
type Step struct {
	Module string                 `yaml:"module"`
	Config map[string]interface{} `yaml:"config"`
}

// Condition represents conditional execution
type Condition struct {
	If   string `yaml:"if"`
	Then []Step `yaml:"then"`
}

// Action represents error/success actions
type Action struct {
	Action   string   `yaml:"action"`
	Level    string   `yaml:"level,omitempty"`
	Channels []string `yaml:"channels,omitempty"`
	Message  string   `yaml:"message,omitempty"`
}

// Settings structures
type CacheSettings struct {
	Enabled bool `yaml:"enabled"`
	TTL     int  `yaml:"ttl"`
}

type StealthSettings struct {
	Enabled             bool   `yaml:"enabled"`
	Level               int    `yaml:"level"` // 0-4 (off to paranoid)
	DelayMin            int    `yaml:"delay_min"`
	DelayMax            int    `yaml:"delay_max"`
	RandomizeUserAgents bool   `yaml:"randomize_user_agents"`
	UseProxies          bool   `yaml:"use_proxies"`
	ProxyRotation       bool   `yaml:"proxy_rotation"`
	FragmentPackets     bool   `yaml:"fragment_packets"`
	AdaptiveProfile     bool   `yaml:"adaptive_profile"`
	UseDecoys           bool   `yaml:"use_decoys"`
	ProxyList           string `yaml:"proxy_list"` // Path to proxy list file
}

type ParallelSettings struct {
	MaxWorkers int `yaml:"max_workers"`
	RateLimit  int `yaml:"rate_limit"`
}

type OutputSettings struct {
	Format    string `yaml:"format"`
	Directory string `yaml:"directory"`
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "pipeline",
		Short: "PADOCCA Pipeline Executor",
		Long: `Execute declarative attack pipelines defined in YAML.
		
Features:
  • Orchestrated multi-stage attacks
  • Conditional execution
  • Parallel processing
  • Result caching
  • Error handling`,
		Run: runPipeline,
	}

	// Flags
	rootCmd.Flags().StringP("file", "f", "pipeline.yaml", "Pipeline configuration file")
	rootCmd.Flags().StringP("target", "t", "", "Primary target")
	rootCmd.Flags().BoolP("dry-run", "d", false, "Dry run mode (validate only)")
	rootCmd.Flags().BoolP("force", "F", false, "Skip manual approvals")
	rootCmd.Flags().StringSliceP("skip", "s", []string{}, "Skip specific stages")
	rootCmd.Flags().StringSliceP("only", "o", []string{}, "Run only specific stages")
	rootCmd.Flags().BoolP("no-cache", "n", false, "Disable caching")
	rootCmd.Flags().BoolP("verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolP("quiet", "q", false, "Quiet mode")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runPipeline(cmd *cobra.Command, args []string) {
	pipelineFile, _ := cmd.Flags().GetString("file")
	target, _ := cmd.Flags().GetString("target")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	force, _ := cmd.Flags().GetBool("force")
	skipStages, _ := cmd.Flags().GetStringSlice("skip")
	onlyStages, _ := cmd.Flags().GetStringSlice("only")
	noCache, _ := cmd.Flags().GetBool("no-cache")
	verbose, _ := cmd.Flags().GetBool("verbose")
	quiet, _ := cmd.Flags().GetBool("quiet")

	// Load pipeline configuration
	pipeline, err := loadPipeline(pipelineFile)
	if err != nil {
		color.Red("[!] Error loading pipeline: %v", err)
		os.Exit(1)
	}

	// Print banner
	if !quiet {
		printBanner()
		color.Cyan("📋 Pipeline: %s v%s", pipeline.Name, pipeline.Version)
		color.Yellow("📝 Description: %s", pipeline.Description)
		color.White("👤 Author: %s", pipeline.Author)
		fmt.Println()
	}

	// Initialize cache if enabled
	if pipeline.Settings.Cache.Enabled && !noCache {
		cacheConfig := &cache.CacheConfig{
			DefaultTTL: time.Duration(pipeline.Settings.Cache.TTL) * time.Second,
			MaxEntries: 10000,
		}
		pipeline.cache = cache.NewCacheManager(cacheConfig)
		defer pipeline.cache.Close()
	}

	// Initialize stealth manager if enabled
	if pipeline.Settings.Stealth.Enabled {
		stealthConfig := &stealth.StealthConfig{
			Enabled:          true,
			Level:            pipeline.Settings.Stealth.Level,
			MinDelay:         pipeline.Settings.Stealth.DelayMin,
			MaxDelay:         pipeline.Settings.Stealth.DelayMax,
			RandomUserAgent:  pipeline.Settings.Stealth.RandomizeUserAgents,
			UseProxies:       pipeline.Settings.Stealth.UseProxies,
			ProxyRotation:    pipeline.Settings.Stealth.ProxyRotation,
			FragmentPackets:  pipeline.Settings.Stealth.FragmentPackets,
			AdaptiveProfile:  pipeline.Settings.Stealth.AdaptiveProfile,
			UseDecoys:        pipeline.Settings.Stealth.UseDecoys,
			JitterEnabled:    true,
			EncodePayloads:   true,
		}
		pipeline.stealthMgr = stealth.NewStealthManager(stealthConfig)
		
		if !quiet {
			color.Green("🥷 Stealth mode enabled (Level: %d)", pipeline.Settings.Stealth.Level)
		}
	}

	// Set target if provided
	if target != "" {
		pipeline.results["target"] = target
	}

	// Dry run mode
	if dryRun {
		color.Yellow("🔍 DRY RUN MODE - Validating pipeline...")
		if err := pipeline.validate(); err != nil {
			color.Red("[!] Pipeline validation failed: %v", err)
			os.Exit(1)
		}
		color.Green("✅ Pipeline validation successful!")
		pipeline.printExecutionPlan(skipStages, onlyStages)
		return
	}

	// Execute pipeline
	pipeline.startTime = time.Now()
	
	err = pipeline.execute(ExecutionOptions{
		SkipStages:     skipStages,
		OnlyStages:     onlyStages,
		Force:          force,
		Verbose:        verbose,
		Quiet:          quiet,
	})
	
	pipeline.endTime = time.Now()
	
	if err != nil {
		color.Red("[!] Pipeline execution failed: %v", err)
		pipeline.handleError(err)
		os.Exit(1)
	}

	// Success actions
	pipeline.handleSuccess()
	
	// Print summary
	if !quiet {
		pipeline.printSummary()
	}
}

func loadPipeline(filename string) (*Pipeline, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read pipeline file: %w", err)
	}

	var pipeline Pipeline
	if err := yaml.Unmarshal(data, &pipeline); err != nil {
		return nil, fmt.Errorf("failed to parse pipeline YAML: %w", err)
	}

	pipeline.results = make(map[string]interface{})
	
	return &pipeline, nil
}

func (p *Pipeline) validate() error {
	// Validate stage dependencies
	stageNames := make(map[string]bool)
	for _, stage := range p.Stages {
		stageNames[stage.Name] = true
	}

	for _, stage := range p.Stages {
		for _, dep := range stage.DependsOn {
			if !stageNames[dep] {
				return fmt.Errorf("stage '%s' depends on unknown stage '%s'", stage.Name, dep)
			}
		}
	}

	// Validate modules exist
	for _, stage := range p.Stages {
		for _, step := range stage.Steps {
			if !moduleExists(step.Module) {
				return fmt.Errorf("unknown module: %s", step.Module)
			}
		}
	}

	return nil
}

// ExecutionOptions contains execution options
type ExecutionOptions struct {
	SkipStages []string
	OnlyStages []string
	Force      bool
	Verbose    bool
	Quiet      bool
}

func (p *Pipeline) execute(opts ExecutionOptions) error {
	// Create output directory
	if err := os.MkdirAll(p.Settings.Output.Directory, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Filter stages based on options
	stages := p.filterStages(opts.SkipStages, opts.OnlyStages)
	
	// Execute stages in order
	for _, stage := range stages {
		// Check dependencies
		if !p.areDependenciesMet(stage) {
			color.Yellow("⏭️  Skipping stage '%s' - dependencies not met", stage.Name)
			continue
		}

		// Manual approval check
		if stage.ManualApproval && !opts.Force {
			if !p.requestApproval(stage) {
				color.Yellow("⏭️  Skipping stage '%s' - approval denied", stage.Name)
				continue
			}
		}

		// Execute stage
		if !opts.Quiet {
			color.Cyan("\n▶️  Executing stage: %s", stage.Name)
			color.White("   %s", stage.Description)
		}

		var err error
		if stage.Parallel {
			err = p.executeStageParallel(stage, opts)
		} else {
			err = p.executeStageSequential(stage, opts)
		}

		if err != nil {
			return fmt.Errorf("stage '%s' failed: %w", stage.Name, err)
		}

		// Mark stage as complete
		p.markStageComplete(stage.Name)
	}

	// Execute conditional steps
	p.executeConditions(opts)

	return nil
}

func (p *Pipeline) executeStageSequential(stage Stage, opts ExecutionOptions) error {
	for i, step := range stage.Steps {
		if !opts.Quiet {
			color.Yellow("  [%d/%d] Running %s...", i+1, len(stage.Steps), step.Module)
		}

		// Apply stealth delay if enabled
		if p.Settings.Stealth.Enabled {
			p.applyStealthDelay()
		}

		// Resolve variables in config
		resolvedConfig := p.resolveVariables(step.Config)
		
		// Execute module
		result, err := p.executeModule(step.Module, resolvedConfig, opts)
		if err != nil {
			return fmt.Errorf("module '%s' failed: %w", step.Module, err)
		}

		// Store result
		p.storeResult(stage.Name, step.Module, result)
	}

	return nil
}

func (p *Pipeline) executeStageParallel(stage Stage, opts ExecutionOptions) error {
	sem := semaphore.NewWeighted(int64(p.Settings.Parallel.MaxWorkers))
	var wg sync.WaitGroup
	errChan := make(chan error, len(stage.Steps))

	for i, step := range stage.Steps {
		wg.Add(1)
		sem.Acquire(context.Background(), 1)

		go func(idx int, s Step) {
			defer wg.Done()
			defer sem.Release(1)

			if !opts.Quiet {
				color.Yellow("  [%d/%d] Running %s (parallel)...", idx+1, len(stage.Steps), s.Module)
			}

			// Apply stealth delay if enabled
			if p.Settings.Stealth.Enabled {
				p.applyStealthDelay()
			}

			// Resolve variables in config
			resolvedConfig := p.resolveVariables(s.Config)
			
			// Execute module
			result, err := p.executeModule(s.Module, resolvedConfig, opts)
			if err != nil {
				errChan <- fmt.Errorf("module '%s' failed: %w", s.Module, err)
				return
			}

			// Store result
			p.storeResult(stage.Name, s.Module, result)
		}(i, step)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Pipeline) executeModule(module string, config map[string]interface{}, opts ExecutionOptions) (interface{}, error) {
	// Check cache first if enabled
	if p.cache != nil {
		cacheKey := p.cache.GenerateKey(module, fmt.Sprintf("%v", config["targets"]), config)
		if entry, exists := p.cache.Get(cacheKey); exists {
			if !opts.Quiet {
				color.Green("    ✓ Using cached result")
			}
			return entry.Result, nil
		}
	}

	// Build command based on module
	cmd := p.buildModuleCommand(module, config)
	
	if opts.Verbose {
		color.Cyan("    Command: %s", strings.Join(cmd.Args, " "))
	}

	// Execute command
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse output
	var result interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		// If not JSON, return as string
		result = string(output)
	}

	// Cache result if enabled
	if p.cache != nil {
		cacheKey := p.cache.GenerateKey(module, fmt.Sprintf("%v", config["targets"]), config)
		ttl := time.Duration(p.Settings.Cache.TTL) * time.Second
		p.cache.Set(cacheKey, module, fmt.Sprintf("%v", config["targets"]), result, ttl)
	}

	return result, nil
}

func (p *Pipeline) buildModuleCommand(module string, config map[string]interface{}) *exec.Cmd {
	// Map module names to actual commands
	binPath := filepath.Join(".", "bin")
	
	cmdMap := map[string]string{
		"subdiscovery":          filepath.Join(binPath, "subdiscovery"),
		"wayback":              filepath.Join(binPath, "wayback"),
		"portscan":             filepath.Join(binPath, "padocca-core"),
		"bruteforce":           filepath.Join(binPath, "bruteforce"),
		"template_scan":        filepath.Join(binPath, "template-scan"),
		"waf_detection":        filepath.Join(binPath, "waf-detect"),
	}

	cmdPath, exists := cmdMap[module]
	if !exists {
		cmdPath = module // Use module name directly if not mapped
	}

	// Build arguments from config
	var args []string
	for key, value := range config {
		// Skip special keys
		if key == "output" || key == "targets" {
			continue
		}

		// Add as flag
		args = append(args, fmt.Sprintf("--%s", key))
		
		// Add value
		switch v := value.(type) {
		case []interface{}:
			for _, item := range v {
				args = append(args, fmt.Sprintf("%v", item))
			}
		case bool:
			if !v {
				args = args[:len(args)-1] // Remove flag if false
			}
		default:
			args = append(args, fmt.Sprintf("%v", value))
		}
	}

	// Add target
	if target, ok := config["targets"]; ok {
		args = append(args, "-t", fmt.Sprintf("%v", target))
	}

	// Add output if specified
	if output, ok := config["output"]; ok {
		args = append(args, "-o", fmt.Sprintf("%v", output))
	}

	// Add JSON output flag
	args = append(args, "--json")

	return exec.Command(cmdPath, args...)
}

func (p *Pipeline) resolveVariables(config map[string]interface{}) map[string]interface{} {
	resolved := make(map[string]interface{})
	
	for key, value := range config {
		switch v := value.(type) {
		case string:
			// Resolve template variables
			if strings.Contains(v, "{{") && strings.Contains(v, "}}") {
				resolved[key] = p.resolveTemplate(v)
			} else {
				resolved[key] = v
			}
		default:
			resolved[key] = v
		}
	}
	
	return resolved
}

func (p *Pipeline) resolveTemplate(template string) string {
	// Simple template resolution
	// Format: {{stage.module.field}}
	
	result := template
	
	// Replace output.directory
	result = strings.ReplaceAll(result, "{{output.directory}}", p.Settings.Output.Directory)
	
	// Replace results from previous stages
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	for key, value := range p.results {
		placeholder := fmt.Sprintf("{{%s}}", key)
		replacement := fmt.Sprintf("%v", value)
		result = strings.ReplaceAll(result, placeholder, replacement)
	}
	
	return result
}

func (p *Pipeline) storeResult(stage, module string, result interface{}) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	key := fmt.Sprintf("%s.%s", stage, module)
	p.results[key] = result
	
	// Also store specific fields for common modules
	if module == "subdiscovery" {
		if data, ok := result.(map[string]interface{}); ok {
			if subs, ok := data["subdomains"].([]interface{}); ok {
				p.results[key+".results"] = subs
				
				// Extract active subdomains
				var active []string
				for _, sub := range subs {
					if subMap, ok := sub.(map[string]interface{}); ok {
						if isActive, ok := subMap["active"].(bool); ok && isActive {
							if domain, ok := subMap["subdomain"].(string); ok {
								active = append(active, domain)
							}
						}
					}
				}
				p.results[key+".active_subdomains"] = active
			}
		}
	}
}

func (p *Pipeline) filterStages(skip, only []string) []Stage {
	var filtered []Stage
	
	skipMap := make(map[string]bool)
	for _, s := range skip {
		skipMap[s] = true
	}
	
	onlyMap := make(map[string]bool)
	for _, s := range only {
		onlyMap[s] = true
	}
	
	for _, stage := range p.Stages {
		// Skip if in skip list
		if skipMap[stage.Name] {
			continue
		}
		
		// Skip if only list is specified and stage not in it
		if len(only) > 0 && !onlyMap[stage.Name] {
			continue
		}
		
		filtered = append(filtered, stage)
	}
	
	return filtered
}

func (p *Pipeline) areDependenciesMet(stage Stage) bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	for _, dep := range stage.DependsOn {
		key := dep + ".complete"
		if complete, ok := p.results[key].(bool); !ok || !complete {
			return false
		}
	}
	
	return true
}

func (p *Pipeline) markStageComplete(name string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	p.results[name+".complete"] = true
}

func (p *Pipeline) requestApproval(stage Stage) bool {
	color.Yellow("\n⚠️  Manual approval required for stage: %s", stage.Name)
	color.White("   %s", stage.Description)
	fmt.Print("   Continue? (y/n): ")
	
	var response string
	fmt.Scanln(&response)
	
	return strings.ToLower(response) == "y" || strings.ToLower(response) == "yes"
}

func (p *Pipeline) executeConditions(opts ExecutionOptions) {
	// Simplified condition execution
	// In a real implementation, would need proper expression evaluation
	
	for _, condition := range p.Conditions {
		// Check condition (simplified)
		if p.evaluateCondition(condition.If) {
			if !opts.Quiet {
				color.Cyan("📌 Executing conditional steps for: %s", condition.If)
			}
			
			for _, step := range condition.Then {
				resolvedConfig := p.resolveVariables(step.Config)
				p.executeModule(step.Module, resolvedConfig, opts)
			}
		}
	}
}

func (p *Pipeline) evaluateCondition(condition string) bool {
	// Simplified condition evaluation
	// In production, use proper expression parser
	
	// Check for "contains" operator
	if strings.Contains(condition, "contains") {
		parts := strings.Split(condition, "contains")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])
			
			// Resolve template variables
			left = p.resolveTemplate(left)
			
			return strings.Contains(left, right)
		}
	}
	
	return false
}

func (p *Pipeline) applyStealthDelay() {
	// Use stealth manager if available
	if p.stealthMgr != nil {
		// Create dummy request to apply stealth delays
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		p.stealthMgr.ApplyStealthToRequest(req)
	} else if p.Settings.Stealth.DelayMin > 0 && p.Settings.Stealth.DelayMax > 0 {
		// Fallback to simple delay
		delay := int64(p.Settings.Stealth.DelayMin) + 
			(time.Now().UnixNano() % int64(p.Settings.Stealth.DelayMax - p.Settings.Stealth.DelayMin))
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}
}

func (p *Pipeline) handleError(err error) {
	for _, action := range p.OnError {
		switch action.Action {
		case "log":
			color.Red("[ERROR] %v", err)
		case "notify":
			// Send notifications (implement based on channels)
			fmt.Printf("Notifying channels: %v\n", action.Channels)
		case "stop":
			os.Exit(1)
		}
	}
}

func (p *Pipeline) handleSuccess() {
	for _, action := range p.OnSuccess {
		switch action.Action {
		case "archive_results":
			// Archive results
			archivePath := filepath.Join(p.Settings.Output.Directory, 
				fmt.Sprintf("archive_%s.tar.gz", time.Now().Format("20060102_150405")))
			color.Green("📦 Archiving results to: %s", archivePath)
			
		case "clean_temp_files":
			// Clean temporary files
			color.Yellow("🧹 Cleaning temporary files...")
			
		case "notify":
			if action.Message != "" {
				color.Green("📢 %s", action.Message)
			}
		}
	}
}

func (p *Pipeline) printExecutionPlan(skip, only []string) {
	fmt.Println()
	color.Cyan("📋 EXECUTION PLAN")
	color.Cyan("═════════════════")
	
	stages := p.filterStages(skip, only)
	
	for i, stage := range stages {
		status := "✓"
		if contains(skip, stage.Name) {
			status = "⏭"
		}
		
		fmt.Printf("\n%s Stage %d: %s\n", status, i+1, stage.Name)
		fmt.Printf("  Description: %s\n", stage.Description)
		
		if len(stage.DependsOn) > 0 {
			fmt.Printf("  Dependencies: %s\n", strings.Join(stage.DependsOn, ", "))
		}
		
		if stage.ManualApproval {
			fmt.Printf("  ⚠️  Requires manual approval\n")
		}
		
		fmt.Printf("  Steps:\n")
		for j, step := range stage.Steps {
			fmt.Printf("    %d. %s\n", j+1, step.Module)
		}
	}
}

func (p *Pipeline) printSummary() {
	duration := p.endTime.Sub(p.startTime)
	
	fmt.Println()
	color.Green("════════════════════════════════════")
	color.Green("       PIPELINE EXECUTION SUMMARY")
	color.Green("════════════════════════════════════")
	
	fmt.Printf("\n📋 Pipeline: %s v%s\n", p.Name, p.Version)
	fmt.Printf("⏱️  Duration: %s\n", duration.Round(time.Second))
	fmt.Printf("📁 Results: %s\n", p.Settings.Output.Directory)
	
	// Cache statistics
	if p.cache != nil {
		stats := p.cache.GetStatistics()
		fmt.Printf("\n📊 Cache Statistics:\n")
		fmt.Printf("  Hit Rate: %v\n", stats["hit_rate"])
		fmt.Printf("  Total Entries: %v\n", stats["total_entries"])
	}
	
	// Stage summary
	fmt.Printf("\n✅ Completed Stages:\n")
	p.mutex.RLock()
	for key, value := range p.results {
		if strings.HasSuffix(key, ".complete") && value.(bool) {
			stageName := strings.TrimSuffix(key, ".complete")
			fmt.Printf("  • %s\n", stageName)
		}
	}
	p.mutex.RUnlock()
	
	color.Green("\n✨ Pipeline completed successfully!")
}

func moduleExists(module string) bool {
	// Check if module binary exists
	knownModules := []string{
		"subdiscovery", "wayback", "portscan", "bruteforce",
		"template_scan", "waf_detection", "ssl_analysis",
		"report_generator", "exploit_validation",
	}
	
	for _, known := range knownModules {
		if module == known {
			return true
		}
	}
	
	return false
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func printBanner() {
	color.Cyan(`
╔══════════════════════════════════════════════════════╗
║       🔄 PADOCCA PIPELINE EXECUTOR 🔄                ║
║         Orchestrated Security Testing                 ║
╚══════════════════════════════════════════════════════╝
`)
}
