#!/usr/bin/env node

/**
 * generate_fix_scripts.js
 * 
 * This script generates automated fix scripts based on error patterns identified
 * in the categorized error data. It creates customized scripts from templates for
 * different error types that can be automatically fixed.
 * 
 * Usage: node generate_fix_scripts.js [options] [input_file]
 * 
 * Options:
 *   --output-dir DIR   Directory to output fix scripts (default: ./scripts/fixes)
 *   --template DIR     Directory containing script templates (default: ./templates)
 *   --dry-run          Show what would be generated without writing files
 *   --verbose          Show detailed output
 */

const fs = require('fs');
const path = require('path');

// Default values
const DEFAULT_INPUT = 'error_categories.json';
const DEFAULT_OUTPUT_DIR = './scripts/fixes';
const DEFAULT_TEMPLATE_DIR = './templates';
const BASE_TEMPLATE = 'fix_script.js';

// Command line arguments
const args = process.argv.slice(2);
const DRY_RUN = args.includes('--dry-run');
const VERBOSE = args.includes('--verbose');
const OUTPUT_DIR = args.find((arg, index) => arg === '--output-dir' && args[index + 1])
    ? args[args.indexOf('--output-dir') + 1]
    : DEFAULT_OUTPUT_DIR;
const TEMPLATE_DIR = args.find((arg, index) => arg === '--template' && args[index + 1])
    ? args[args.indexOf('--template') + 1]
    : DEFAULT_TEMPLATE_DIR;
const INPUT_FILE = args.find(arg => !arg.startsWith('--') && args.indexOf(arg) !== args.indexOf('--output-dir') + 1)
    || DEFAULT_INPUT;

// Error patterns and their corresponding fix configurations
const FIX_CONFIGURATIONS = {
    // Security fixes
    'SEC001': {
        description: 'SQL Injection Prevention',
        pattern: /(\w+)\s*=\s*["'].*?\$\{.*?}.*?["']/g,
        replacement: '$1 = db.escape($2)',
        validate: (content) => content.includes('db.escape'),
        extensions: ['.js', '.ts']
    },

    // Performance fixes
    'PERF001': {
        description: 'Inefficient Loop Optimization',
        pattern: /for\s*\(\s*let\s+i\s*=\s*0\s*;\s*i\s*<\s*(\w+)\.length\s*;\s*i\+\+\s*\)/g,
        replacement: 'for (let i = 0, len = $1.length; i < len; i++)',
        extensions: ['.js', '.ts', '.jsx', '.tsx']
    },

    // Style fixes
    'STYLE001': {
        description: 'Indentation Standardization',
        pattern: /^( {2,}|\t+)/gm,
        replacement: '  ',
        extensions: ['.js', '.ts', '.jsx', '.tsx', '.css', '.scss', '.html']
    },
    'STYLE002': {
        description: 'Line Length Reduction',
        pattern: /^(.{80,})$/gm,
        replacement: (match) => {
            // Complex replacement logic for different file types
            return match.length > 120 ? `${match.slice(0, 80)}\\${match.slice(80)}` : match;
        },
        extensions: ['.js', '.ts', '.jsx', '.tsx']
    },

    // Documentation fixes
    'DOC001': {
        description: 'Missing Function Documentation',
        pattern: /function\s+(\w+)\s*\(([^)]*)\)/g,
        replacement: (match, name, params) => {
            const paramList = params.split(',').map(p => p.trim()).filter(Boolean);
            let jsdoc = '/**\n';
            jsdoc += ` * ${name}\n`;
            jsdoc += ` *\n`;

            if (paramList.length > 0) {
                paramList.forEach(param => {
                    const paramName = param.split('=')[0].trim();
                    jsdoc += ` * @param {any} ${paramName} - Description for ${paramName}\n`;
                });
            }

            jsdoc += ` * @returns {any} Description of return value\n`;
            jsdoc += ` */\n${match}`;
            return jsdoc;
        },
        extensions: ['.js', '.ts']
    },

    // Type safety fixes
    'TYPE001': {
        description: 'Explicit Type Conversion',
        pattern: /(\w+)\s*=\s*(\w+)\s*([+\-*\/])/g,
        replacement: '$1 = Number($2) $3',
        extensions: ['.js', '.ts']
    }
};

/**
 * Reads and parses the input error categories file
 * @param {string} filePath - Path to the error categories JSON file
 * @returns {object} - Parsed error categories
 */
function readErrorCategories(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(content);
    } catch (error) {
        console.error(`Error reading error categories file: ${error.message}`);
        process.exit(1);
    }
}

/**
 * Reads the fix script template file
 * @param {string} templateDir - Directory containing the template
 * @returns {string} - Template content
 */
function readFixScriptTemplate(templateDir) {
    try {
        const templatePath = path.join(templateDir, BASE_TEMPLATE);
        return fs.readFileSync(templatePath, 'utf8');
    } catch (error) {
        console.error(`Error reading template file: ${error.message}`);
        process.exit(1);
    }
}

/**
 * Generates a fix script for a specific error pattern
 * @param {string} template - The base template content
 * @param {string} errorCode - The error code to fix
 * @param {object} config - Configuration for the fix
 * @returns {string} - Generated script content
 */
function generateFixScript(template, errorCode, config) {
    // Replace placeholders in the template
    return template
        .replace(/ERROR_CODE/g, errorCode)
        .replace(/Description of the issue/g, config.description)
        .replace(/pattern-to-match/g, config.pattern.toString().slice(1, -1))
        .replace(/'replacement-pattern'/g, typeof config.replacement === 'function'
            ? config.replacement.toString()
            : `'${config.replacement}'`)
        .replace(/\['.js', '.ts', '.jsx', '.tsx'\]/g, JSON.stringify(config.extensions));
}

/**
 * Writes a fix script to a file
 * @param {string} outputDir - Directory to write the script to
 * @param {string} errorCode - Error code the script fixes
 * @param {string} content - Script content
 */
function writeFixScript(outputDir, errorCode, content) {
    try {
        // Create output directory if it doesn't exist
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        const outputPath = path.join(outputDir, `fix_${errorCode.toLowerCase().replace(/\//g, '_')}.js`);
        fs.writeFileSync(outputPath, content, { mode: 0o755 }); // Executable permission
        console.log(`Generated fix script: ${outputPath}`);
    } catch (error) {
        console.error(`Error writing fix script: ${error.message}`);
    }
}

/**
 * Main function
 */
function main() {
    console.log(`Generating fix scripts from ${INPUT_FILE}...`);

    // Read error categories
    const errorCategories = readErrorCategories(INPUT_FILE);

    // Read fix script template
    const template = readFixScriptTemplate(TEMPLATE_DIR);

    // Track generated scripts
    const generatedScripts = [];

    // Process each severity category
    for (const [severity, categories] of Object.entries(errorCategories.categories)) {
        for (const [category, errors] of Object.entries(categories)) {
            for (const error of errors) {
                // Skip errors that can't be automatically fixed
                if (!error.automatedFix) {
                    if (VERBOSE) {
                        console.log(`Skipping ${error.errorCode} (${error.description}): Not automatable`);
                    }
                    continue;
                }

                // Check if we have a fix configuration for this error
                const {errorCode} = error;
                const fixConfig = FIX_CONFIGURATIONS[errorCode];

                if (!fixConfig) {
                    if (VERBOSE) {
                        console.log(`Skipping ${errorCode}: No fix configuration available`);
                    }
                    continue;
                }

                // Generate the fix script
                const scriptContent = generateFixScript(template, errorCode, fixConfig);

                // Write or simulate writing the script
                if (DRY_RUN) {
                    console.log(`[Dry run] Would generate fix script for ${errorCode} (${error.description})`);
                    if (VERBOSE) {
                        console.log('--- Script preview ---');
                        console.log(scriptContent.slice(0, 200) + '...');
                        console.log('---------------------');
                    }
                } else {
                    writeFixScript(OUTPUT_DIR, errorCode, scriptContent);
                }

                generatedScripts.push({
                    errorCode,
                    description: error.description,
                    occurrences: error.count,
                    path: path.join(OUTPUT_DIR, `fix_${errorCode.toLowerCase().replace(/\//g, '_')}.js`)
                });
            }
        }
    }

    // Print summary
    console.log('\nFix Script Generation Summary:');
    console.log(`Total scripts generated: ${generatedScripts.length}`);

    if (generatedScripts.length > 0) {
        console.log('\nGenerated scripts:');
        generatedScripts.forEach(script => {
            console.log(`- ${script.path} (fixes ${script.occurrences} occurrences of ${script.errorCode}: ${script.description})`);
        });

        console.log('\nExample usage:');
        if (generatedScripts.length > 0) {
            const example = generatedScripts[0];
            console.log(`  ${example.path} [--dry-run] [--verbose] [target_directory]`);
        }
    }

    if (DRY_RUN) {
        console.log('\nThis was a dry run. No files were actually written.');
    }
}

// Execute main function
main();