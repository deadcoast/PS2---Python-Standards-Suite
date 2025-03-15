#!/usr/bin/env node

/**
 * track_metrics.js
 * 
 * This script tracks code quality metrics over time and generates reports
 * comparing current metrics with historical data.
 * 
 * Usage: node track_metrics.js [options] [current_analysis_file]
 * 
 * Options:
 *   --history-file FILE   Path to the metrics history file (default: metrics_history.json)
 *   --report-file FILE    Path to output report file (default: metrics_report.md)
 *   --baseline FILE       Compare against a specific baseline file
 *   --format FORMAT       Output format (md, json) (default: md)
 *   --chart               Generate charts for visualization
 *   --verbose             Show detailed output
 */

const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

// Default values
const DEFAULT_CURRENT = 'error_categories.json';
const DEFAULT_HISTORY = 'metrics_history.json';
const DEFAULT_REPORT = 'metrics_report.md';
const DEFAULT_FORMAT = 'md';

// Command line arguments
const args = process.argv.slice(2);
const VERBOSE = args.includes('--verbose');
const GENERATE_CHARTS = args.includes('--chart');
const HISTORY_FILE = args.find((arg, index) => arg === '--history-file' && args[index + 1])
    ? args[args.indexOf('--history-file') + 1]
    : DEFAULT_HISTORY;
const REPORT_FILE = args.find((arg, index) => arg === '--report-file' && args[index + 1])
    ? args[args.indexOf('--report-file') + 1]
    : DEFAULT_REPORT;
const BASELINE_FILE = args.find((arg, index) => arg === '--baseline' && args[index + 1])
    ? args[args.indexOf('--baseline') + 1]
    : null;
const OUTPUT_FORMAT = args.find((arg, index) => arg === '--format' && args[index + 1])
    ? args[args.indexOf('--format') + 1]
    : DEFAULT_FORMAT;
const CURRENT_FILE = args.find(arg => !arg.startsWith('--') &&
    args.indexOf(arg) !== args.indexOf('--history-file') + 1 &&
    args.indexOf(arg) !== args.indexOf('--report-file') + 1 &&
    args.indexOf(arg) !== args.indexOf('--baseline') + 1 &&
    args.indexOf(arg) !== args.indexOf('--format') + 1)
    || DEFAULT_CURRENT;

/**
 * Reads and parses JSON files
 * @param {string} filePath - Path to the JSON file
 * @returns {object} - Parsed JSON data
 */
function readJsonFile(filePath) {
    try {
        if (!fs.existsSync(filePath)) {
            return null;
        }
        const content = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(content);
    } catch (error) {
        console.error(`Error reading ${filePath}: ${error.message}`);
        return null;
    }
}

/**
 * Updates the metrics history file with current metrics
 * @param {string} historyFile - Path to the history file
 * @param {object} currentMetrics - Current metrics to add
 */
function updateHistoryFile(historyFile, currentMetrics) {
    try {
        let history = [];

        // Read existing history if available
        if (fs.existsSync(historyFile)) {
            const content = fs.readFileSync(historyFile, 'utf8');
            history = JSON.parse(content);
        }

        // Add current metrics to history
        history.push({
            date: new Date().toISOString().split('T')[0],
            commit: getGitCommit(),
            metrics: currentMetrics
        });

        // Sort by date
        history.sort((a, b) => new Date(a.date) - new Date(b.date));

        // Write updated history
        fs.writeFileSync(historyFile, JSON.stringify(history, null, 2));

        console.log(`Updated metrics history in ${historyFile}`);
    } catch (error) {
        console.error(`Error updating history file: ${error.message}`);
    }
}

/**
 * Gets the current git commit hash
 * @returns {string} - Current git commit hash or "unknown"
 */
function getGitCommit() {
    try {
        return childProcess.execSync('git rev-parse HEAD').toString().trim();
    } catch (error) {
        return "unknown";
    }
}

/**
 * Calculates the percentage change between two values
 * @param {number} current - Current value
 * @param {number} previous - Previous value
 * @returns {string} - Formatted percentage change
 */
function calculateChange(current, previous) {
    if (previous === 0) {
        return current === 0 ? "0%" : "∞%";
    }

    const change = ((current - previous) / previous) * 100;
    return `${change > 0 ? '+' : ''}${change.toFixed(1)}%`;
}

/**
 * Extracts metrics from an analysis file
 * @param {object} analysisData - Analysis data
 * @returns {object} - Extracted metrics
 */
function extractMetrics(analysisData) {
    if (!analysisData) {
        return null;
    }

    // Extract summary metrics
    const summary = analysisData.summary || {};

    // Calculate additional metrics
    const criticalPercentage = summary.totalIssues > 0
        ? (summary.criticalIssues / summary.totalIssues) * 100
        : 0;

    const automationPercentage = summary.totalIssues > 0
        ? (summary.automatedFixCandidates / summary.totalIssues) * 100
        : 0;

    // Estimate technical debt in hours
    const technicalDebt = (summary.criticalIssues * 4) +
        (summary.importantIssues * 2) +
        (summary.minorIssues * 0.5);

    // Extract category metrics
    const categoryBreakdown = {};
    const categories = analysisData.categories || {};

    Object.entries(categories).forEach(([severity, categoryGroup]) => {
        Object.entries(categoryGroup).forEach(([category, issues]) => {
            if (!categoryBreakdown[category]) {
                categoryBreakdown[category] = 0;
            }

            categoryBreakdown[category] += issues.reduce((sum, issue) => sum + issue.count, 0);
        });
    });

    // Estimate code quality score (0-100)
    const maxScore = 100;
    const criticalPenalty = summary.criticalIssues * 5;
    const importantPenalty = summary.importantIssues * 1;
    const minorPenalty = summary.minorIssues * 0.2;

    let qualityScore = maxScore - criticalPenalty - importantPenalty - minorPenalty;
    qualityScore = Math.max(0, Math.min(100, qualityScore));

    return {
        timestamp: new Date().toISOString(),
        totalFiles: summary.totalFilesAnalyzed || 0,
        filesWithIssues: summary.filesWithIssues || 0,
        totalIssues: summary.totalIssues || 0,
        criticalIssues: summary.criticalIssues || 0,
        importantIssues: summary.importantIssues || 0,
        minorIssues: summary.minorIssues || 0,
        automatedFixCandidates: summary.automatedFixCandidates || 0,
        manualReviewRequired: summary.manualReviewRequired || 0,
        criticalPercentage: criticalPercentage.toFixed(1),
        automationPercentage: automationPercentage.toFixed(1),
        technicalDebt: technicalDebt.toFixed(1),
        qualityScore: qualityScore.toFixed(1),
        categoryBreakdown
    };
}

/**
 * Generates a comparison report between current and baseline metrics
 * @param {object} currentMetrics - Current metrics
 * @param {object} baselineMetrics - Baseline metrics
 * @returns {object} - Comparison data
 */
function generateComparison(currentMetrics, baselineMetrics) {
    if (!currentMetrics || !baselineMetrics) {
        return null;
    }

    // Calculate changes for key metrics
    const comparison = {
        period: {
            from: baselineMetrics.timestamp.split('T')[0],
            to: currentMetrics.timestamp.split('T')[0]
        },
        metrics: {
            totalIssues: {
                before: baselineMetrics.totalIssues,
                after: currentMetrics.totalIssues,
                change: calculateChange(currentMetrics.totalIssues, baselineMetrics.totalIssues)
            },
            criticalIssues: {
                before: baselineMetrics.criticalIssues,
                after: currentMetrics.criticalIssues,
                change: calculateChange(currentMetrics.criticalIssues, baselineMetrics.criticalIssues)
            },
            importantIssues: {
                before: baselineMetrics.importantIssues,
                after: currentMetrics.importantIssues,
                change: calculateChange(currentMetrics.importantIssues, baselineMetrics.importantIssues)
            },
            minorIssues: {
                before: baselineMetrics.minorIssues,
                after: currentMetrics.minorIssues,
                change: calculateChange(currentMetrics.minorIssues, baselineMetrics.minorIssues)
            },
            technicalDebt: {
                before: baselineMetrics.technicalDebt,
                after: currentMetrics.technicalDebt,
                change: calculateChange(parseFloat(currentMetrics.technicalDebt), parseFloat(baselineMetrics.technicalDebt))
            },
            qualityScore: {
                before: baselineMetrics.qualityScore,
                after: currentMetrics.qualityScore,
                change: calculateChange(parseFloat(currentMetrics.qualityScore), parseFloat(baselineMetrics.qualityScore))
            },
            automationPercentage: {
                before: baselineMetrics.automationPercentage,
                after: currentMetrics.automationPercentage,
                change: calculateChange(parseFloat(currentMetrics.automationPercentage), parseFloat(baselineMetrics.automationPercentage))
            }
        },
        categories: {}
    };

    // Compare category breakdowns
    const allCategories = new Set([
        ...Object.keys(currentMetrics.categoryBreakdown || {}),
        ...Object.keys(baselineMetrics.categoryBreakdown || {})
    ]);

    allCategories.forEach(category => {
        const currentCount = (currentMetrics.categoryBreakdown || {})[category] || 0;
        const baselineCount = (baselineMetrics.categoryBreakdown || {})[category] || 0;

        comparison.categories[category] = {
            before: baselineCount,
            after: currentCount,
            change: calculateChange(currentCount, baselineCount)
        };
    });

    return comparison;
}

/**
 * Generates a markdown report
 * @param {object} currentMetrics - Current metrics
 * @param {object} comparison - Comparison with baseline
 * @param {string} reportFile - Output file path
 */
function generateMarkdownReport(currentMetrics, comparison, reportFile) {
    try {
        let report = `# Code Quality Metrics Report\n\n`;

        if (comparison) {
            report += `**Report Period**: ${comparison.period.from} to ${comparison.period.to}  \n`;
        } else {
            report += `**Report Date**: ${currentMetrics.timestamp.split('T')[0]}  \n`;
        }

        report += `**Codebase Version**: ${getGitCommit()}  \n`;
        report += `**Generated**: ${new Date().toISOString().split('T')[0]}\n\n`;

        // Executive summary
        report += `## Executive Summary\n\n`;

        if (comparison) {
            const totalIssuesChange = parseFloat(comparison.metrics.totalIssues.change);
            const qualityScoreChange = parseFloat(comparison.metrics.qualityScore.change);

            report += `This report summarizes the code quality improvement metrics for the specified period. `;
            report += `During this time, the total number of issues has changed by ${comparison.metrics.totalIssues.change} `;
            report += `(from ${comparison.metrics.totalIssues.before} to ${comparison.metrics.totalIssues.after}). `;
            report += `The overall code quality score has ${qualityScoreChange >= 0 ? 'improved' : 'decreased'} `;
            report += `from ${comparison.metrics.qualityScore.before} to ${comparison.metrics.qualityScore.after}.\n\n`;
        } else {
            report += `This report provides a snapshot of the current code quality metrics. `;
            report += `Currently, there are ${currentMetrics.totalIssues} issues identified, `;
            report += `with a code quality score of ${currentMetrics.qualityScore}.\n\n`;
        }

        // Key metrics
        report += `## Key Metrics\n\n`;

        if (comparison) {
            report += `| Metric | Before | After | Change | Target |\n`;
            report += `|--------|--------|-------|--------|--------|\n`;
            report += `| Total Issues | ${comparison.metrics.totalIssues.before} | ${comparison.metrics.totalIssues.after} | ${comparison.metrics.totalIssues.change} | - |\n`;
            report += `| Critical Issues | ${comparison.metrics.criticalIssues.before} | ${comparison.metrics.criticalIssues.after} | ${comparison.metrics.criticalIssues.change} | 0 |\n`;
            report += `| Important Issues | ${comparison.metrics.importantIssues.before} | ${comparison.metrics.importantIssues.after} | ${comparison.metrics.importantIssues.change} | < 50 |\n`;
            report += `| Minor Issues | ${comparison.metrics.minorIssues.before} | ${comparison.metrics.minorIssues.after} | ${comparison.metrics.minorIssues.change} | < 200 |\n`;
            report += `| Technical Debt (hours) | ${comparison.metrics.technicalDebt.before} | ${comparison.metrics.technicalDebt.after} | ${comparison.metrics.technicalDebt.change} | < 500 |\n`;
            report += `| Quality Score | ${comparison.metrics.qualityScore.before} | ${comparison.metrics.qualityScore.after} | ${comparison.metrics.qualityScore.change} | > 80 |\n`;
            report += `| Automation Potential | ${comparison.metrics.automationPercentage.before}% | ${comparison.metrics.automationPercentage.after}% | ${comparison.metrics.automationPercentage.change} | > 70% |\n`;
        } else {
            report += `| Metric | Current | Target |\n`;
            report += `|--------|---------|--------|\n`;
            report += `| Total Issues | ${currentMetrics.totalIssues} | - |\n`;
            report += `| Critical Issues | ${currentMetrics.criticalIssues} | 0 |\n`;
            report += `| Important Issues | ${currentMetrics.importantIssues} | < 50 |\n`;
            report += `| Minor Issues | ${currentMetrics.minorIssues} | < 200 |\n`;
            report += `| Technical Debt (hours) | ${currentMetrics.technicalDebt} | < 500 |\n`;
            report += `| Quality Score | ${currentMetrics.qualityScore} | > 80 |\n`;
            report += `| Automation Potential | ${currentMetrics.automationPercentage}% | > 70% |\n`;
        }

        report += `\n`;

        // Issue distribution by category
        report += `## Issue Distribution by Category\n\n`;

        if (comparison) {
            report += `### Before Remediation\n\n`;

            report += `| Category | Count | Percentage |\n`;
            report += `|----------|-------|------------|\n`;

            const baselineTotalIssues = comparison.metrics.totalIssues.before;
            Object.entries(comparison.categories).forEach(([category, data]) => {
                const percentage = baselineTotalIssues > 0
                    ? ((data.before / baselineTotalIssues) * 100).toFixed(1)
                    : '0.0';

                report += `| ${category} | ${data.before} | ${percentage}% |\n`;
            });

            report += `\n### After Remediation\n\n`;

            report += `| Category | Count | Percentage | Change |\n`;
            report += `|----------|-------|------------|--------|\n`;

            const currentTotalIssues = comparison.metrics.totalIssues.after;
            Object.entries(comparison.categories).forEach(([category, data]) => {
                const percentage = currentTotalIssues > 0
                    ? ((data.after / currentTotalIssues) * 100).toFixed(1)
                    : '0.0';

                report += `| ${category} | ${data.after} | ${percentage}% | ${data.change} |\n`;
            });
        } else {
            report += `| Category | Count | Percentage |\n`;
            report += `|----------|-------|------------|\n`;

            const totalIssues = currentMetrics.totalIssues;
            Object.entries(currentMetrics.categoryBreakdown || {}).forEach(([category, count]) => {
                const percentage = totalIssues > 0
                    ? ((count / totalIssues) * 100).toFixed(1)
                    : '0.0';

                report += `| ${category} | ${count} | ${percentage}% |\n`;
            });
        }

        report += `\n`;

        // Next steps
        report += `## Next Steps\n\n`;

        if (comparison) {
            const totalIssuesChange = parseFloat(comparison.metrics.totalIssues.change);

            if (totalIssuesChange < 0) {
                report += `1. Continue with the current remediation strategy which has successfully reduced issues by ${Math.abs(totalIssuesChange.toFixed(1))}%\n`;
                report += `2. Focus next on ${getHighestCategory(comparison.categories)} issues which still have the highest count\n`;
                report += `3. Update standards documentation based on common fixes applied\n`;
                report += `4. Implement preventive measures for the most frequently fixed issues\n`;
            } else {
                report += `1. Review current remediation strategy as issues have increased by ${totalIssuesChange.toFixed(1)}%\n`;
                report += `2. Prioritize fixing ${getHighestCategory(comparison.categories)} issues which have the highest count\n`;
                report += `3. Consider implementing stricter code review guidelines\n`;
                report += `4. Explore additional automated checks that can prevent these issues\n`;
            }
        } else {
            report += `1. Prioritize addressing the ${currentMetrics.criticalIssues} critical issues first\n`;
            report += `2. Focus on ${getHighestCategory(currentMetrics.categoryBreakdown)} issues which have the highest count\n`;
            report += `3. Implement automated fixes for the ${currentMetrics.automatedFixCandidates} automatable issues\n`;
            report += `4. Schedule regular follow-up analysis to track progress\n`;
        }

        report += `\n`;

        // Appendix with methodology
        report += `## Appendix: Methodology\n\n`;
        report += `This report was generated using the following methodology:\n\n`;
        report += `1. **Data Collection**: Linting and static analysis tools were used to identify code issues\n`;
        report += `2. **Metrics Calculation**: Issues were categorized by severity and type, then quantified\n`;
        report += `3. **Technical Debt Estimation**: Critical issues (4 hours), Important issues (2 hours), Minor issues (0.5 hours)\n`;
        report += `4. **Quality Score Calculation**: Base score of 100 with deductions for each issue based on severity\n`;

        // Write the report to file
        fs.writeFileSync(reportFile, report);
        console.log(`Generated markdown report: ${reportFile}`);
    } catch (error) {
        console.error(`Error generating markdown report: ${error.message}`);
    }
}

/**
 * Helper function to get the category with the highest count
 * @param {object} categoryData - Category data object
 * @returns {string} - Category with highest count
 */
function getHighestCategory(categoryData) {
    if (!categoryData || Object.keys(categoryData).length === 0) {
        return 'unknown';
    }

    let highestCategory = '';
    let highestCount = -1;

    Object.entries(categoryData).forEach(([category, data]) => {
        const count = typeof data === 'number' ? data : (data.after || data.before || 0);

        if (count > highestCount) {
            highestCount = count;
            highestCategory = category;
        }
    });

    return highestCategory;
}

/**
 * Generates a JSON report
 * @param {object} currentMetrics - Current metrics
 * @param {object} comparison - Comparison with baseline
 * @param {string} reportFile - Output file path
 */
function generateJsonReport(currentMetrics, comparison, reportFile) {
    try {
        const report = {
            generatedAt: new Date().toISOString(),
            codebaseVersion: getGitCommit(),
            currentMetrics,
            comparison
        };

        fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));
        console.log(`Generated JSON report: ${reportFile}`);
    } catch (error) {
        console.error(`Error generating JSON report: ${error.message}`);
    }
}

/**
 * Main function
 */
function main() {
    console.log('Code Quality Metrics Tracker');
    console.log(`Analyzing current metrics from: ${CURRENT_FILE}`);

    // Read current analysis data
    const currentAnalysis = readJsonFile(CURRENT_FILE);

    if (!currentAnalysis) {
        console.error(`Could not read current analysis file: ${CURRENT_FILE}`);
        process.exit(1);
    }

    // Extract metrics from current analysis
    const currentMetrics = extractMetrics(currentAnalysis);

    if (!currentMetrics) {
        console.error('Failed to extract metrics from current analysis');
        process.exit(1);
    }

    // Update metrics history
    updateHistoryFile(HISTORY_FILE, currentMetrics);

    // Determine baseline for comparison
    let baselineAnalysis = null;
    let baselineMetrics = null;
    let comparison = null;

    if (BASELINE_FILE) {
        // Use specified baseline file
        console.log(`Using specified baseline file: ${BASELINE_FILE}`);
        baselineAnalysis = readJsonFile(BASELINE_FILE);

        if (baselineAnalysis) {
            baselineMetrics = extractMetrics(baselineAnalysis);
            comparison = generateComparison(currentMetrics, baselineMetrics);
        } else {
            console.warn(`Could not read baseline file: ${BASELINE_FILE}`);
        }
    } else {
        // Try to use history file for comparison
        const history = readJsonFile(HISTORY_FILE);

        if (history && Array.isArray(history) && history.length > 1) {
            // Use the second most recent entry as baseline
            const baselineEntry = history[history.length - 2];
            baselineMetrics = baselineEntry.metrics;
            comparison = generateComparison(currentMetrics, baselineMetrics);

            console.log(`Using historical baseline from: ${baselineEntry.date}`);
        } else {
            console.log('No historical baseline available for comparison');
        }
    }

    // Generate report
    if (OUTPUT_FORMAT === 'json') {
        generateJsonReport(currentMetrics, comparison, REPORT_FILE);
    } else {
        generateMarkdownReport(currentMetrics, comparison, REPORT_FILE);
    }

    console.log('Metrics tracking completed successfully');
}

// Execute main function
main();