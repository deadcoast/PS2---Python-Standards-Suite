#!/bin/bash

# lint_export.sh
# 
# This script runs linting tools against a codebase and exports the results
# to a structured format for further analysis.
#
# Usage: ./lint_export.sh [OPTIONS] [DIRECTORY]
#
# Options:
#   --help          Show this help message
#   --output FILE   Output file (default: project_analysis.md)
#   --format FMT    Output format (md, json, csv)
#   --tools LIST    Comma-separated list of tools to run
#   --config FILE   Custom config file
#   --verbose       Show detailed output

# Default values
OUTPUT_FILE="project_analysis.md"
OUTPUT_FORMAT="md"
TARGET_DIR="."
VERBOSE=false
TOOLS="eslint,stylelint,lighthouse,axe"
CONFIG_FILE=""

# Function to show help
show_help() {
  grep '^#' "$0" | grep -v '^#!/bin/bash' | sed 's/^# //; s/^#//'
  exit 0
}

# Process command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --help)
      show_help
      ;;
    --output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    --format)
      OUTPUT_FORMAT="$2"
      shift 2
      ;;
    --tools)
      TOOLS="$2"
      shift 2
      ;;
    --config)
      CONFIG_FILE="$2"
      shift 2
      ;;
    --verbose)
      VERBOSE=true
      shift
      ;;
    *)
      if [[ -d "$1" ]]; then
        TARGET_DIR="$1"
      else
        echo "Error: Unknown option or invalid directory: $1"
        exit 1
      fi
      shift
      ;;
  esac
done

# Check if target directory exists
if [[ ! -d "$TARGET_DIR" ]]; then
  echo "Error: Target directory does not exist: $TARGET_DIR"
  exit 1
fi

# Ensure output directory exists
OUTPUT_DIR=$(dirname "$OUTPUT_FILE")
mkdir -p "$OUTPUT_DIR"

# Create temporary directory for linting results
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Function to run a linting tool and capture output
run_tool() {
  local tool=$1
  local output_file="$TEMP_DIR/${tool}_output.json"
  
  echo "Running $tool against $TARGET_DIR..."
  
  case "$tool" in
    eslint)
      # Run ESLint
      if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        npx eslint "$TARGET_DIR" -c "$CONFIG_FILE" -f json > "$output_file"
      else
        npx eslint "$TARGET_DIR" -f json > "$output_file"
      fi
      ;;
    stylelint)
      # Run Stylelint
      if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        npx stylelint "$TARGET_DIR/**/*.css" "$TARGET_DIR/**/*.scss" --config "$CONFIG_FILE" -f json > "$output_file"
      else
        npx stylelint "$TARGET_DIR/**/*.css" "$TARGET_DIR/**/*.scss" -f json > "$output_file"
      fi
      ;;
    lighthouse)
      # Run Lighthouse (for web projects)
      if [[ -f "$TARGET_DIR/index.html" ]]; then
        npx lighthouse "$TARGET_DIR/index.html" --output json --output-path "$output_file" --chrome-flags="--headless" --quiet
      else
        echo "Skipping lighthouse: No index.html found"
        return
      fi
      ;;
    axe)
      # Run axe accessibility checker (for web projects)
      if [[ -f "$TARGET_DIR/index.html" ]]; then
        npx axe "$TARGET_DIR/index.html" --save "$output_file" --exit
      else
        echo "Skipping axe: No index.html found"
        return
      fi
      ;;
    tsc)
      # Run TypeScript compiler for type checking
      npx tsc --project "$TARGET_DIR" --noEmit --pretty false --formatDiagnostics > "$output_file"
      ;;
    *)
      echo "Unknown tool: $tool"
      return 1
      ;;
  esac
  
  if [[ $? -eq 0 ]]; then
    echo "✓ $tool completed successfully"
  else
    echo "⚠ $tool reported issues"
  fi
}

# Run each tool
IFS=',' read -ra TOOL_ARRAY <<< "$TOOLS"
for tool in "${TOOL_ARRAY[@]}"; do
  run_tool "$tool"
done

# Function to generate statistics from all tool outputs
generate_statistics() {
  local total_files=0
  local files_with_issues=0
  local total_issues=0
  local critical_issues=0
  local important_issues=0
  local minor_issues=0
  
  # Process ESLint results
  if [[ -f "$TEMP_DIR/eslint_output.json" ]]; then
    # Use jq to extract the statistics if available
    if command -v jq &> /dev/null; then
      total_files=$(jq 'length' "$TEMP_DIR/eslint_output.json")
      files_with_issues=$(jq '[.[] | select(.errorCount > 0 or .warningCount > 0)] | length' "$TEMP_DIR/eslint_output.json")
      total_issues=$(jq '[.[] | .errorCount + .warningCount] | add' "$TEMP_DIR/eslint_output.json")
      critical_issues=$(jq '[.[] | .messages[] | select(.severity == 2 and .message | contains("security") or contains("vulnerability"))] | length' "$TEMP_DIR/eslint_output.json")
      important_issues=$(jq '[.[] | .messages[] | select(.severity == 2 and (.message | contains("security") or contains("vulnerability") | not))] | length' "$TEMP_DIR/eslint_output.json")
      minor_issues=$(jq '[.[] | .messages[] | select(.severity == 1)] | length' "$TEMP_DIR/eslint_output.json")
    fi
  fi
  
  # Add statistics from other tools here
  
  echo "Total Files Analyzed: $total_files"
  echo "Files with Issues: $files_with_issues"
  echo "Total Issues: $total_issues"
  echo "Critical Issues: $critical_issues"
  echo "Important Issues: $important_issues"
  echo "Minor Issues: $minor_issues"
}

# Generate the report file based on format
case "$OUTPUT_FORMAT" in
  md)
    {
      echo "# Project Code Quality Analysis"
      echo
      echo "**Analysis Date:** $(date +%Y-%m-%d)"
      echo "**Codebase Version:** $(git rev-parse HEAD 2>/dev/null || echo 'N/A')"
      echo "**Tools Used:** ${TOOLS//,/, }"
      echo
      echo "## Summary Statistics"
      echo
      echo "| Metric | Count |"
      echo "|--------|-------|"
      stats=$(generate_statistics)
      while IFS=: read -r key value; do
        echo "| $key | $value |"
      done <<< "$stats"
      echo
      echo "## Error Categories"
      echo
      # Here we would add more detailed sections for each error category
      # For demonstration, we'll add placeholder sections
      echo "### 1. Critical Issues"
      echo
      echo "#### 1.1 Security Vulnerabilities"
      echo
      echo "| Error Code | Description | Count | Files | Automated Fix |"
      echo "|------------|-------------|-------|-------|---------------|"
      # Add rows here based on actual data
      
      # Other sections would follow...
      
      echo
      echo "## Error Details"
      echo
      # Generate detailed error listings by file
      
      echo
      echo "## Next Steps"
      echo
      echo "1. Generate fix scripts for automated remediation candidates"
      echo "2. Prioritize manual fixes based on impact"
      echo "3. Update coding standards to prevent future occurrences"
      echo "4. Schedule follow-up analysis after initial fixes"
    } > "$OUTPUT_FILE"
    ;;
    
  json)
    # Generate JSON output
    # This would be a more structured approach with jq
    if command -v jq &> /dev/null; then
      {
        echo "{"
        echo "  \"metadata\": {"
        echo "    \"analysisDate\": \"$(date +%Y-%m-%d)\","
        echo "    \"codebaseVersion\": \"$(git rev-parse HEAD 2>/dev/null || echo 'N/A')\","
        echo "    \"toolsUsed\": [$(echo "$TOOLS" | sed 's/,/","/g' | sed 's/^/"/' | sed 's/$/"/' )]"
        echo "  },"
        echo "  \"summary\": {"
        stats=$(generate_statistics)
        # Process stats into JSON format
        # ... (code to convert stats to JSON)
        echo "  }"
        echo "  // Additional JSON data would be added here"
        echo "}"
      } > "$OUTPUT_FILE"
    else
      echo "Error: jq command not found, required for JSON output"
      exit 1
    fi
    ;;
    
  csv)
    # Generate CSV output
    # Simpler format focusing on individual errors
    {
      echo "File,Line,Column,Rule,Severity,Message,Tool"
      # Process each tool's output and convert to CSV format
      # ... (code to generate CSV rows)
    } > "$OUTPUT_FILE"
    ;;
    
  *)
    echo "Error: Unsupported output format: $OUTPUT_FORMAT"
    exit 1
    ;;
esac

echo "Linting analysis completed and exported to $OUTPUT_FILE"

# Generate categorized error file for further processing
echo "Generating categorized error file..."
node "$(dirname "$0")/categorize_errors.js" "$OUTPUT_FILE" "${OUTPUT_FILE%.*}_categories.json"

echo "Process completed successfully."
exit 0