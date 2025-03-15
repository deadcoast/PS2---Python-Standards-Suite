#!/usr/bin/env node

/**
 * Automated Fix Script Template
 * 
 * This script provides a framework for creating automated fixes for common code issues.
 * It can be customized based on specific error patterns and requirements.
 */

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

// Configuration
const CONFIG = {
    // Error code this script addresses
    errorCode: 'ERROR_CODE',

    // Description of the issue being fixed
    description: 'Description of the issue',

    // Regular expression to identify the issue
    pattern: /pattern-to-match/g,

    // Replacement pattern or function
    replacement: 'replacement-pattern',

    // File extensions to process
    extensions: ['.js', '.ts', '.jsx', '.tsx'],

    // Directories to exclude
    excludeDirs: ['node_modules', 'dist', 'build'],

    // Optional: Custom validation function
    validate: (content, filePath) => true,

    // Optional: Pre-processing function
    preProcess: (content, filePath) => content,

    // Optional: Post-processing function
    postProcess: (content, filePath) => content,

    // Optional: Backup files before modifying
    createBackups: true,

    // Optional: Dry run (don't actually modify files)
    dryRun: false
};

// Command line arguments
const args = process.argv.slice(2);
const VERBOSE = args.includes('--verbose');
const DRY_RUN = args.includes('--dry-run') || CONFIG.dryRun;
const TARGET_DIR = args.find(arg => !arg.startsWith('--')) || '.';

// Statistics
const stats = {
    filesScanned: 0,
    filesModified: 0,
    errorsFixed: 0,
    errors: []
};

/**
 * Process a single file
 */
function processFile(filePath) {
    try {
        stats.filesScanned++;

        // Read file content
        let content = fs.readFileSync(filePath, 'utf8');

        // Skip if file doesn't match our pattern
        if (!CONFIG.pattern.test(content)) {
            if (VERBOSE) console.log(`No matches in ${filePath}`);
            return;
        }

        // Validate file is eligible for fix
        if (CONFIG.validate && !CONFIG.validate(content, filePath)) {
            if (VERBOSE) console.log(`Validation failed for ${filePath}`);
            return;
        }

        // Pre-process content if needed
        if (CONFIG.preProcess) {
            content = CONFIG.preProcess(content, filePath);
        }

        // Create backup if configured
        if (CONFIG.createBackups && !DRY_RUN) {
            fs.writeFileSync(`${filePath}.bak`, content);
            if (VERBOSE) console.log(`Created backup: ${filePath}.bak`);
        }

        // Count matches
        const matches = content.match(CONFIG.pattern);
        const matchCount = matches ? matches.length : 0;

        // Apply fix
        let newContent;
        if (typeof CONFIG.replacement === 'function') {
            newContent = content.replace(CONFIG.pattern, CONFIG.replacement);
        } else {
            newContent = content.replace(CONFIG.pattern, CONFIG.replacement);
        }

        // Post-process content if needed
        if (CONFIG.postProcess) {
            newContent = CONFIG.postProcess(newContent, filePath);
        }

        // Write modified content
        if (!DRY_RUN) {
            fs.writeFileSync(filePath, newContent);
        }

        stats.filesModified++;
        stats.errorsFixed += matchCount;

        console.log(`Fixed ${matchCount} issues in ${filePath}${DRY_RUN ? ' (dry run)' : ''}`);

    } catch (error) {
        stats.errors.push({ file: filePath, error: error.message });
        console.error(`Error processing ${filePath}: ${error.message}`);
    }
}

/**
 * Walk directory recursively and process files
 */
function processDirectory(dirPath) {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });

    for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);

        if (entry.isDirectory()) {
            // Skip excluded directories
            if (CONFIG.excludeDirs.includes(entry.name)) {
                continue;
            }
            processDirectory(fullPath);
        } else if (entry.isFile()) {
            // Process only files with matching extensions
            const ext = path.extname(entry.name);
            if (CONFIG.extensions.includes(ext)) {
                processFile(fullPath);
            }
        }
    }
}

/**
 * Print statistics and summary
 */
function printSummary() {
    console.log('\n--- Fix Script Summary ---');
    console.log(`Error code: ${CONFIG.errorCode}`);
    console.log(`Description: ${CONFIG.description}`);
    console.log(`Files scanned: ${stats.filesScanned}`);
    console.log(`Files modified: ${stats.filesModified}`);
    console.log(`Issues fixed: ${stats.errorsFixed}`);

    if (stats.errors.length > 0) {
        console.log('\nErrors encountered:');
        stats.errors.forEach(error => {
            console.log(`- ${error.file}: ${error.error}`);
        });
    }

    if (DRY_RUN) {
        console.log('\nThis was a dry run. No files were actually modified.');
    }
}

/**
 * Main execution
 */
function main() {
    console.log(`Starting fix script for ${CONFIG.errorCode}`);
    console.log(`Target directory: ${TARGET_DIR}`);
    console.log(`Mode: ${DRY_RUN ? 'Dry run' : 'Live run'}\n`);

    processDirectory(TARGET_DIR);
    printSummary();

    // Exit with error code if any errors occurred
    process.exit(stats.errors.length > 0 ? 1 : 0);
}

// Execute main function
main();