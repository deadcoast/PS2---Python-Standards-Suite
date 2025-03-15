#!/usr/bin/env node

/**
 * categorize_errors.js
 * 
 * This script processes linting output and categorizes errors into structured formats
 * for easier analysis, prioritization, and remediation planning.
 * 
 * Usage: node categorize_errors.js [input_file] [output_file]
 */

const fs = require('fs');
const path = require('path');

// Default file paths
const DEFAULT_INPUT = 'project_analysis.md';
const DEFAULT_OUTPUT = 'error_categories.json';

// Error category mappings
const ERROR_CATEGORIES = {
    // Security issues
    'security/no-eval': { category: 'security', subCategory: 'security', severity: 'critical', description: 'Forbidden eval usage', automatedFix: true },
    'security/detect-non-literal-regexp': { category: 'security', subCategory: 'security', severity: 'critical', description: 'Non-literal RegExp', automatedFix: false },
    'security/detect-object-injection': { category: 'security', subCategory: 'security', severity: 'critical', description: 'Potential object injection', automatedFix: false },

    // Performance issues
    'optimize/no-inefficient-loop': { category: 'performance', subCategory: 'performance', severity: 'critical', description: 'Inefficient loop pattern', automatedFix: true },
    'optimize/prefer-object-spread': { category: 'performance', subCategory: 'performance', severity: 'important', description: 'Use object spread instead of Object.assign', automatedFix: true },

    // Accessibility issues
    'jsx-a11y/alt-text': { category: 'accessibility', subCategory: 'accessibility', severity: 'critical', description: 'Missing alt text for images', automatedFix: false },
    'jsx-a11y/aria-role': { category: 'accessibility', subCategory: 'accessibility', severity: 'important', description: 'Invalid ARIA role', automatedFix: true },

    // Code maintainability
    'complexity': { category: 'maintainability', subCategory: 'maintainability', severity: 'important', description: 'Function exceeds complexity threshold', automatedFix: false },
    'max-depth': { category: 'maintainability', subCategory: 'maintainability', severity: 'important', description: 'Function exceeds maximum depth', automatedFix: false },
    'max-lines': { category: 'maintainability', subCategory: 'maintainability', severity: 'important', description: 'File exceeds maximum lines', automatedFix: false },

    // Type safety issues
    'typescript/no-explicit-any': { category: 'typeSafety', subCategory: 'typeSafety', severity: 'important', description: 'Use of explicit any type', automatedFix: false },
    'typescript/explicit-function-return-type': { category: 'typeSafety', subCategory: 'typeSafety', severity: 'important', description: 'Missing return type', automatedFix: true },

    // Style issues
    'indent': { category: 'style', subCategory: 'style', severity: 'minor', description: 'Inconsistent indentation', automatedFix: true },
    'quotes': { category: 'style', subCategory: 'style', severity: 'minor', description: 'Inconsistent quote style', automatedFix: true },
    'max-len': { category: 'style', subCategory: 'style', severity: 'minor', description: 'Line length exceeds maximum', automatedFix: true },

    // Documentation issues
    'jsdoc/require-jsdoc': { category: 'documentation', subCategory: 'documentation', severity: 'minor', description: 'Missing function documentation', automatedFix: true },
    'jsdoc/require-param': { category: 'documentation', subCategory: 'documentation', severity: 'minor', description: 'Missing parameter documentation', automatedFix: true }
};

// Default category for unknown error codes
const DEFAULT_CATEGORY = {
    category: 'unknown',
    subCategory: 'unknown',
    severity: 'minor',
    description: 'Unknown issue',
    automatedFix: false
};

/**
 * Parse a markdown file containing linting results
 * @param {string} filePath - Path to the markdown file
 * @returns {object} - Structured data extracted from markdown
 */
function parseMarkdownLintResults(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');

        // Extract summary statistics
        const summaryMatch = content.match(/## Summary Statistics\n\n\|.*\|\n\|.*\|([\s\S]*?)(?=\n\n##|$)/);
        const summary = {};

        if (summaryMatch && summaryMatch[1]) {
            const summaryLines = summaryMatch[1].trim().split('\n');
            summaryLines.forEach(line => {
                const [_, key, value] = line.match(/\| (.*?) \| (.*?) \|/);
                summary[key.trim().toLowerCase().replace(/\s+/g, '_')] = parseInt(value.trim(), 10) || 0;
            });
        }

        // Extract error details
        const errorDetailsMatch = content.match(/## Error Details\n\n([\s\S]*?)(?=\n\n##|$)/);
        const fileErrors = {};

        if (errorDetailsMatch && errorDetailsMatch[1]) {
            const fileMatches = errorDetailsMatch[1].matchAll(/### (.*?)\n\n```\n([\s\S]*?)```/g);

            for (const fileMatch of fileMatches) {
                const filePath = fileMatch[1].trim();
                const errors = [];

                const errorLines = fileMatch[2].trim().split('\n');
                errorLines.forEach(line => {
                    const match = line.match(/Line (\d+): \[(.*?)\] (.*)/);
                    if (match) {
                        errors.push({
                            line: parseInt(match[1], 10),
                            code: match[2],
                            message: match[3]
                        });
                    }
                });

                fileErrors[filePath] = errors;
            }
        }

        return {
            summary,
            fileErrors
        };
    } catch (error) {
        console.error(`Error parsing markdown file: ${error.message}`);
        process.exit(1);
    }
}

/**
 * Parse a JSON file containing linting results
 * @param {string} filePath - Path to the JSON file
 * @returns {object} - Structured data extracted from JSON
 */
function parseJsonLintResults(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(content);
    } catch (error) {
        console.error(`Error parsing JSON file: ${error.message}`);
        process.exit(1);
    }
}

/**
 * Categorize errors based on their error codes
 * @param {object} lintResults - Parsed linting results
 * @returns {object} - Categorized errors
 */
function categorizeErrors(lintResults) {
    const result = {
        metadata: {
            analysisDate: new Date().toISOString().split('T')[0],
            codebaseVersion: process.env.GIT_COMMIT || 'unknown',
            toolsUsed: ['eslint', 'stylelint', 'lighthouse', 'axe'].filter(Boolean)
        },
        summary: {
            totalFilesAnalyzed: 0,
            filesWithIssues: 0,
            totalIssues: 0,
            criticalIssues: 0,
            importantIssues: 0,
            minorIssues: 0,
            automatedFixCandidates: 0,
            manualReviewRequired: 0
        },
        categories: {
            critical: {},
            important: {},
            minor: {}
        },
        fileDetails: {},
        fixCandidates: {
            automated: [],
            manual: []
        }
    };

    // Initialize category counters
    const categories = new Set();
    const errorCodeCounts = {};

    // Process file errors
    const fileErrors = lintResults.fileErrors || {};
    result.summary.totalFilesAnalyzed = Object.keys(fileErrors).length;
    result.summary.filesWithIssues = Object.keys(fileErrors).length;

    Object.entries(fileErrors).forEach(([filePath, errors]) => {
        result.fileDetails[filePath] = { errors: [] };

        errors.forEach(error => {
            // Get category info
            const categoryInfo = ERROR_CATEGORIES[error.code] || DEFAULT_CATEGORY;
            const { category, subCategory, severity, description, automatedFix } = categoryInfo;

            // Count issue by severity
            result.summary.totalIssues++;
            if (severity === 'critical') {
              result.summary.criticalIssues++;
            }
            if (severity === 'important') {
              result.summary.importantIssues++;
            }
            if (severity === 'minor') {
              result.summary.minorIssues++;
            }

            // Count by automation potential
            if (automatedFix) {
                result.summary.automatedFixCandidates++;
            } else {
                result.summary.manualReviewRequired++;
            }

            // Track categories
            categories.add(category);

            // Track error code counts
            errorCodeCounts[error.code] = (errorCodeCounts[error.code] || 0) + 1;

            // Add to categories structure
            if (!result.categories[severity][category]) {
                result.categories[severity][category] = [];
            }

            // Check if error code already exists in the category
            const existingError = result.categories[severity][category].find(e => e.errorCode === error.code);

            if (existingError) {
                existingError.count++;
                if (!existingError.files.includes(filePath)) {
                    existingError.files.push(filePath);
                }
            } else {
                result.categories[severity][category].push({
                    errorCode: error.code,
                    description: description || error.message,
                    count: 1,
                    files: [filePath],
                    automatedFix,
                    fixComplexity: automatedFix ? 'low' : 'high',
                    fixScriptTemplate: automatedFix ? `fix_${error.code.replace(/\//g, '_')}.js` : null
                });
            }

            // Add to file details
            result.fileDetails[filePath].errors.push({
                line: error.line || 0,
                column: error.column || 0,
                errorCode: error.code,
                message: error.message || description,
                severity,
                context: error.context || ''
            });
        });
    });

    // Generate fix candidates
    Object.entries(errorCodeCounts).forEach(([errorCode, count]) => {
        const categoryInfo = ERROR_CATEGORIES[errorCode] || DEFAULT_CATEGORY;

        if (categoryInfo.automatedFix) {
            result.fixCandidates.automated.push({
                pattern: errorCode,
                occurrences: count,
                fixApproach: `Apply standardized fix for ${categoryInfo.description}`,
                estimatedImpact: `Resolve ${count} instances of ${errorCode} across the codebase`
            });
        } else {
            result.fixCandidates.manual.push({
                pattern: errorCode,
                occurrences: count,
                reason: categoryInfo.severity === 'critical' ? 'Critical issue requiring careful review' : 'Complex logic changes needed',
                recommendedApproach: `Manually review each instance of ${categoryInfo.description}`
            });
        }
    });

    return result;
}

/**
 * Main function
 */
function main() {
    // Parse command line arguments
    const args = process.argv.slice(2);
    const inputFile = args[0] || DEFAULT_INPUT;
    const outputFile = args[1] || DEFAULT_OUTPUT;

    console.log(`Categorizing errors from ${inputFile} to ${outputFile}...`);

    // Determine file type and parse accordingly
    const ext = path.extname(inputFile).toLowerCase();
    let lintResults;

    if (ext === '.md') {
        lintResults = parseMarkdownLintResults(inputFile);
    } else if (ext === '.json') {
        lintResults = parseJsonLintResults(inputFile);
    } else {
        console.error(`Unsupported file type: ${ext}`);
        process.exit(1);
    }

    // Categorize errors
    const categorizedErrors = categorizeErrors(lintResults);

    // Write output
    fs.writeFileSync(outputFile, JSON.stringify(categorizedErrors, null, 2));

    console.log(`Error categorization complete. Results written to ${outputFile}`);
    console.log(`Summary: ${categorizedErrors.summary.totalIssues} issues found (${categorizedErrors.summary.criticalIssues} critical, ${categorizedErrors.summary.importantIssues} important, ${categorizedErrors.summary.minorIssues} minor)`);
    console.log(`${categorizedErrors.summary.automatedFixCandidates} can be fixed automatically, ${categorizedErrors.summary.manualReviewRequired} require manual review`);
}

// Execute the main function
main();