package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/coolguy1771/guardrail/pkg/validator"
)

const (
	// Formatting constants.
	tabwriterPadding = 2
	separatorLength  = 80
)

// Version is the tool version embedded in SARIF output. Set by main via ldflags.
//
//nolint:gochecknoglobals // Set by main at startup from build-time ldflags
var Version = "dev"

// UseColor controls whether emoji and ANSI escape codes appear in text output.
// Initialised at startup via TTY detection; override with --no-color or NO_COLOR.
//
//nolint:gochecknoglobals // Package-level state intentionally shared across output paths
var UseColor = defaultUseColor()

func defaultUseColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// Reporter handles output formatting for validation findings.
type Reporter interface {
	Report(findings []validator.Finding, writer io.Writer) error
}

// Format represents the output format.
type Format string

const (
	FormatText  Format = "text"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// New creates a new reporter based on the specified format.
func New(format Format) Reporter {
	switch format {
	case FormatJSON:
		return &JSONReporter{}
	case FormatSARIF:
		return &SARIFReporter{}
	case FormatText:
		return &TextReporter{}
	default:
		return &TextReporter{}
	}
}

// TextReporter outputs findings in human-readable text format.
type TextReporter struct{}

// Report outputs findings in text format.
func (r *TextReporter) Report(findings []validator.Finding, writer io.Writer) error {
	if len(findings) == 0 {
		if UseColor {
			fmt.Fprintln(writer, "✅ No issues found.")
		} else {
			fmt.Fprintln(writer, "No issues found.")
		}
		return nil
	}

	// Group findings by severity
	grouped := groupBySeverity(findings)

	// Summary
	fmt.Fprintf(writer, "Found %d issue(s)\n\n", len(findings))

	// Create a tabwriter for aligned output
	w := tabwriter.NewWriter(writer, 0, 0, tabwriterPadding, ' ', 0)
	defer w.Flush()

	// Output findings by severity (highest first)
	for _, severity := range []validator.Severity{
		validator.SeverityCritical,
		validator.SeverityHigh,
		validator.SeverityMedium,
		validator.SeverityLow,
		validator.SeverityInfo,
	} {
		if severityFindings, ok := grouped[severity]; ok {
			fmt.Fprintf(w, "%s %s (%d)\n", getSeverityIcon(severity), severity, len(severityFindings))
			fmt.Fprintln(w, strings.Repeat("-", separatorLength))

			for _, finding := range severityFindings {
				fmt.Fprintf(w, "Rule:\t%s - %s\n", finding.RuleID, finding.RuleName)
				fmt.Fprintf(w, "Resource:\t%s/%s", finding.Kind, finding.Resource)
				if finding.Namespace != "" {
					fmt.Fprintf(w, " (namespace: %s)", finding.Namespace)
				}
				fmt.Fprintln(w)
				fmt.Fprintf(w, "Message:\t%s\n", finding.Message)
				if finding.Remediation != "" {
					fmt.Fprintf(w, "Remediation:\t%s\n", finding.Remediation)
				}
				fmt.Fprintln(w)
			}
		}
	}

	return nil
}

// JSONReporter outputs findings in JSON format.
type JSONReporter struct{}

// JSONReport represents the JSON output structure.
type JSONReport struct {
	Timestamp string              `json:"timestamp"`
	Summary   Summary             `json:"summary"`
	Findings  []validator.Finding `json:"findings"`
}

// Summary represents the summary of findings.
type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
}

// Report outputs findings in JSON format.
func (r *JSONReporter) Report(findings []validator.Finding, writer io.Writer) error {
	grouped := groupBySeverity(findings)
	bySeverity := make(map[string]int)

	for severity, severityFindings := range grouped {
		bySeverity[string(severity)] = len(severityFindings)
	}

	report := JSONReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Summary: Summary{
			Total:      len(findings),
			BySeverity: bySeverity,
		},
		Findings: findings,
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report) //nolint:musttag // JSONReport struct has proper json tags
}

// SARIFReporter outputs findings in SARIF format.
type SARIFReporter struct{}

// SARIF structures.
type SARIF struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name"`
	ShortDescription     SARIFMultiformatString  `json:"shortDescription"`
	FullDescription      SARIFMultiformatString  `json:"fullDescription"`
	HelpUri              string                  `json:"helpUri,omitempty"`
	Help                 *SARIFMultiformatString `json:"help,omitempty"`
	DefaultConfiguration SARIFConfiguration      `json:"defaultConfiguration"`
	Properties           *SARIFRuleProperties    `json:"properties,omitempty"`
}

type SARIFRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type SARIFMultiformatString struct {
	Text string `json:"text"`
}

type SARIFConfiguration struct {
	Level string `json:"level"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// buildSARIFRules returns SARIF rule descriptors for all catalog entries.
// Building from the catalog (rather than from findings) means SARIF consumers always
// see the full set of available checks, even for runs with zero violations.
func buildSARIFRules() []SARIFRule {
	rules := make([]SARIFRule, 0, len(validator.Catalog))
	for _, meta := range validator.Catalog {
		helpText := meta.Remediation
		rules = append(rules, SARIFRule{
			ID:               meta.ID,
			Name:             meta.Name,
			ShortDescription: SARIFMultiformatString{Text: meta.Name},
			FullDescription:  SARIFMultiformatString{Text: meta.Description},
			HelpUri:          fmt.Sprintf("https://github.com/coolguy1771/guardrail#%s", strings.ToLower(meta.ID)),
			Help:             &SARIFMultiformatString{Text: helpText},
			DefaultConfiguration: SARIFConfiguration{
				Level: severityToSARIFLevel(meta.DefaultSeverity),
			},
			Properties: &SARIFRuleProperties{Tags: []string{"kubernetes", "rbac", "security"}},
		})
	}
	return rules
}

// Report outputs findings in SARIF format.
func (r *SARIFReporter) Report(findings []validator.Finding, writer io.Writer) error {
	// Build rule list from the full catalog so SARIF consumers know all available checks,
	// not just the ones that produced findings in this run.
	rules := buildSARIFRules()

	// Build results
	var results []SARIFResult
	for _, finding := range findings {
		uri := fmt.Sprintf("%s/%s", finding.Kind, finding.Resource)
		if finding.Namespace != "" {
			uri = fmt.Sprintf("namespace/%s/%s", finding.Namespace, uri)
		}

		results = append(results, SARIFResult{
			RuleID: finding.RuleID,
			Level:  severityToSARIFLevel(finding.Severity),
			Message: SARIFMessage{
				Text: finding.Message,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: uri,
						},
					},
				},
			},
		})
	}

	sarif := SARIF{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "guardrail",
						Version:        Version,
						InformationURI: "https://github.com/coolguy1771/guardrail",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarif)
}

// Helper functions

func groupBySeverity(findings []validator.Finding) map[validator.Severity][]validator.Finding {
	grouped := make(map[validator.Severity][]validator.Finding)
	for _, finding := range findings {
		grouped[finding.Severity] = append(grouped[finding.Severity], finding)
	}
	return grouped
}

func getSeverityIcon(severity validator.Severity) string {
	if UseColor {
		switch severity {
		case validator.SeverityCritical:
			return "🔴"
		case validator.SeverityHigh:
			return "🟠"
		case validator.SeverityMedium:
			return "🟡"
		case validator.SeverityLow:
			return "🔵"
		case validator.SeverityInfo:
			return "ℹ️ "
		default:
			return "• "
		}
	}
	switch severity {
	case validator.SeverityCritical:
		return "[CRIT]  "
	case validator.SeverityHigh:
		return "[HIGH]  "
	case validator.SeverityMedium:
		return "[MED]   "
	case validator.SeverityLow:
		return "[LOW]   "
	case validator.SeverityInfo:
		return "[INFO]  "
	default:
		return "[?]     "
	}
}

func severityToSARIFLevel(severity validator.Severity) string {
	switch severity {
	case validator.SeverityCritical, validator.SeverityHigh:
		return "error"
	case validator.SeverityMedium:
		return "warning"
	case validator.SeverityLow, validator.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// ReportToFile writes the report to a file.
func ReportToFile(findings []validator.Finding, format Format, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	reporter := New(format)
	return reporter.Report(findings, file)
}
