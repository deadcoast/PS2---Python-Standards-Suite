# Converter Management UI

## Overview

The Converter Management Interface provides players with a comprehensive ASCII UI for monitoring and controlling resource conversion processes, including multi-step production chains, ASCII Progress Bars, and ASCII Effeciency. This document outlines the design, components, and implementation details for this interface.

## Design Goals

1. **Intuitive Production Chain Management**: Allow players to easily visualize and manage complex production chains in a Retro ASCII Aesthetic
2. **Real-time Efficiency Monitoring**: Provide clear visual feedback with ASCII on conversion efficiency factors
3. **Interactive Control**: Enable hands-on management of conversion processes with ASCII aesthetics.
4. **Clear Resource Visualization**: Visualize resource flows and conversions VIA an ASCII Dynamic Element
5. **Chain Optimization Tools**: Help players optimize their production chains

## Interface Components

- These interfaces should be implemented as is, with the retro ASCII aesthetic for stylilized menus.

### Converter Dashboard

The main ASCII dashboard provides an overview of all converters and active conversion processes:

```
+---------------------------------------------------------------+
|                    CONVERTER DASHBOARD                        |
+-----------------------------------+--------------------------->
| CONVERTERS    | ACTIVE PROCESSES       | PRODUCTION METRICS   |
| - Smelter #1  | - Iron Ore → Ingots    | Efficiency: 87%      |
| - Smelter #2  | - Copper Ore → Ingots  | Throughput: 45/min   |
| - Assembler   | - Ingots → Components  | Energy Use: 350kW    |
| - Refinery    | - Crude Oil → Fuel     | Queue: 3 processes   |
+---------------+------------------------+---------------------->
|                                                               |
|                     CHAIN VISUALIZATION                       |
|                                                               |
|  [ORE EXTRACTOR] → [SMELTER] → [ASSEMBLER] → [STORAGE]        |
|                                                               |
+-----------------------------------+--------------------------->
|              CONTROLS             |        EFFICIENCY         |
| [START] [PAUSE] [STOP] [OPTIMIZE] | Base: 0.8  Tech: 1.2      |
|                                   | Quality: 1.1  Env: 0.95   |
+-----------------------------------+--------------------------->
```

### Converter Details View

Detailed view of ASCII selected converter with all its stats and controls:

```
+---------------------------------------------------------------+
|                  CONVERTER: ADVANCED SMELTER                  |
+-----------------------------------+--------------------------->
| STATUS: ACTIVE                    | TIER: 3                   |
| EFFICIENCY: 87%                   | ENERGY: 120kW/45kW        |
| UTILIZATION: 65%                  | UPTIME: 3h 45m            |
+-----------------------------------+--------------------------->
|                                                               |
|                ACTIVE CONVERSION PROCESSES                    |
|                                                               |
|[#142] Iron Ore → Iron Ingots (76% complete) [PAUSE] [STOP]    |
|[#143] Copper Ore → Copper Ingots (42% complete) [PAUSE] [STOP]|
|                                                               |
+--------------------------------------------------------------->
|                                                               |
|                   AVAILABLE RECIPES                           |
|                                                               |
| • Iron Ore → Iron Ingots (Base Eff: 0.9) [START]              |
| • Copper Ore → Copper Ingots (Base Eff: 0.85) [START]         |
| • Gold Ore → Gold Ingots (Base Eff: 0.7) [START]              |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|                   EFFICIENCY FACTORS                          |
|                                                               |
| • Base Efficiency: 0.8                                        |
| • Quality Modifier: 1.1 (Good quality inputs)                 |
| • Technology Modifier: 1.2 (Level 4 tech)                     |
| • Environmental Modifier: 0.95 (Minor hazard)                 |
| → Applied Efficiency: 0.87 (0.8 × 1.1 × 1.2 × 0.95)           |
|                                                               |
+---------------------------------------------------------------+
```

### Chain Management Interface

Interface for creating and managing multi-step production chains:

```
+---------------------------------------------------------------+
|                  PRODUCTION CHAIN MANAGEMENT                  |
+---------------------------------------------------------------+
|                                                               |
|                     ACTIVE CHAINS                             |
|                                                               |
| [#24] Basic Electronics (3 steps, 45% complete)               |
|   › Step 1: Copper Ore → Copper Ingots [COMPLETED]            |
|   › Step 2: Iron Ore → Iron Plates [IN PROGRESS]              |
|   › Step 3: Copper + Iron → Electronic Components [PENDING]   |
|                                                               |
| [#25] Advanced Alloy (2 steps, 30% complete)                  |
|   › Step 1: Titanium Ore → Titanium Ingots [IN PROGRESS]      |
|   › Step 2: Titanium + Steel → Advanced Alloy [PENDING]       |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|                     CHAIN CREATOR                             |
|                                                               |
|  Step 1: [SMELTER #1] [IRON ORE → IRON INGOTS] [▼]            |
|  Step 2: [ASSEMBLER] [IRON INGOTS → IRON PLATES] [▼]          |
|  Step 3: [FABRICATOR] [IRON PLATES → COMPONENTS] [▼]          |
|                                                               |
|  [+ ADD STEP]               [SAVE AS TEMPLATE] [START CHAIN]  |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|                     CHAIN TEMPLATES                           |
|                                                               |
|  • Basic Electronics (3 steps) [LOAD] [DELETE]                |
|  • Advanced Alloy (2 steps) [LOAD] [DELETE]                   |
|  • Fuel Processing (4 steps) [LOAD] [DELETE]                  |
|                                                               |
+---------------------------------------------------------------+
```

### Efficiency Monitor

Detailed visualization of ASCII efficiency factors with historical tracking:

```
+---------------------------------------------------------------+
|                     EFFICIENCY MONITOR                        |
+---------------------------------------------------------------+
|                                                               |
|  OVERALL EFFICIENCY: 92%                                      |
|  ██████████████████▒▒▒▒ (TREND: +5% from last cycle)          |
|                                                               |
|  EFFICIENCY BREAKDOWN:                                        |
|  • Base Efficiency:         0.85  ███████████▒▒▒▒             |
|  • Quality Modifier:        1.15  ███████████████▒            |
|  • Technology Modifier:     1.25  ████████████████▒           |
|  • Environmental Modifier:  0.95  ████████████▒▒▒             |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|  EFFICIENCY HISTORY:                                          |
|  ↗                                                            |
|    ↗       ↗                                                  |
|  ↗   ↘   ↗   ↘   ↗                                            |
|     ↘         ↘                                               |
|  Last 24 hours (Avg: 87%)                                     |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|  EFFICIENCY OPTIMIZATION SUGGESTIONS:                         |
|  • Upgrade converter to Tier 4 (+10% base efficiency)         |
|  • Research "Advanced Metallurgy" (+15% tech modifier)        |
|  • Use higher quality Iron Ore (+8% quality modifier)         |
|  • Address nearby hazard (+5% environmental modifier)         |
|                                                               |
+---------------------------------------------------------------+
```

## Implementation Components

### 1. ConverterDashboard Component

Main entry point for converter management:

```typescript
interface ConverterDashboardProps {
  converters: ConverterSummary[];
  activeProcesses: ConversionProcessSummary[];
  activeChains: ChainStatusSummary[];
  onConverterSelect: (converterId: string) => void;
  onProcessSelect: (processId: string) => void;
  onChainSelect: (chainId: string) => void;
}

const ConverterDashboard: React.FC<ConverterDashboardProps> = ({
  converters,
  activeProcesses,
  activeChains,
  onConverterSelect,
  onProcessSelect,
  onChainSelect,
}) => {
  // Implementation
};
```

### 2. ConverterDetailsView Component

Detailed view of a single converter:

```typescript
interface ConverterDetailsViewProps {
  converter: ConverterDetail;
  activeProcesses: ConversionProcessDetail[];
  availableRecipes: RecipeDetail[];
  onStartProcess: (recipeId: string) => void;
  onPauseProcess: (processId: string) => void;
  onStopProcess: (processId: string) => void;
  onBack: () => void;
}

const ConverterDetailsView: React.FC<ConverterDetailsViewProps> = ({
  converter,
  activeProcesses,
  availableRecipes,
  onStartProcess,
  onPauseProcess,
  onStopProcess,
  onBack,
}) => {
  // Implementation
};
```

### 3. ChainManagementInterface Component

Interface for managing production chains:

```typescript
interface ChainManagementInterfaceProps {
  activeChains: ChainStatus[];
  availableConverters: ConverterSummary[];
  availableRecipes: RecipeDetail[];
  savedTemplates: ChainTemplate[];
  onStartChain: (steps: ChainStep[]) => void;
  onPauseChain: (chainId: string) => void;
  onResumeChain: (chainId: string) => void;
  onCancelChain: (chainId: string) => void;
  onSaveTemplate: (template: ChainTemplate) => void;
  onLoadTemplate: (templateId: string) => void;
  onDeleteTemplate: (templateId: string) => void;
}

const ChainManagementInterface: React.FC<ChainManagementInterfaceProps> = ({
  activeChains,
  availableConverters,
  availableRecipes,
  savedTemplates,
  onStartChain,
  onPauseChain,
  onResumeChain,
  onCancelChain,
  onSaveTemplate,
  onLoadTemplate,
  onDeleteTemplate,
}) => {
  // Implementation
};
```

### 4. EfficiencyMonitor Component

Visualizes efficiency factors and history:

```typescript
interface EfficiencyMonitorProps {
  converter: ConverterDetail;
  efficiencyHistory: EfficiencyHistoryEntry[];
  optimizationSuggestions: OptimizationSuggestion[];
}

const EfficiencyMonitor: React.FC<EfficiencyMonitorProps> = ({
  converter,
  efficiencyHistory,
  optimizationSuggestions,
}) => {
  // Implementation
};
```

### 5. ChainVisualization Component

Visualizes production chains as a graph:

```typescript
interface ChainVisualizationProps {
  chain: ChainStatus;
  converters: Record<string, ConverterSummary>;
  recipes: Record<string, RecipeDetail>;
  interactive?: boolean;
  onNodeClick?: (nodeId: string, type: 'converter' | 'recipe') => void;
}

const ChainVisualization: React.FC<ChainVisualizationProps> = ({
  chain,
  converters,
  recipes,
  interactive = false,
  onNodeClick,
}) => {
  // Implementation using D3 or React Flow for visualization
};
```

## UI/UX Considerations

### Visual Design Elements

1. **Color Coding**:

   - Green: Optimal efficiency (>90%)
   - Yellow: Moderate efficiency (70-90%)
   - Orange: Low efficiency (50-70%)
   - Red: Poor efficiency (<50%)
   - Blue: Inactive or paused

2. **Icons**:

   - Different icons for converter types (smelter, assembler, refinery)
   - Status icons (active, paused, error)
   - Resource type icons

3. **Progress Indicators**:
   - Circular progress for individual processes
   - Linear progress for chains
   - Animated flows for resource transfers

### Interaction Patterns

1. **Drag and Drop**:

   - Drag recipes to converters to start processes
   - Drag and drop chain steps to reorder them
   - Drag resources between storage and converters

2. **Contextual Controls**:

   - Right-click menus for common actions
   - Hover tooltips with detailed information
   - Double-click to open detailed views

3. **Real-time Updates**:
   - Efficiency graphs update in real-time
   - Process progress bars animate smoothly
   - Resource levels change visually as they're consumed/produced

## Implementation Plan

### Phase 1: Core Components

1. Develop `ConverterDashboard` component
2. Implement `ConverterDetailsView` component
3. Create basic process management controls
4. Implement simple efficiency display

### Phase 2: Chain Management

1. Develop `ChainManagementInterface` component
2. Implement `ChainVisualization` component
3. Create chain step configuration UI
4. Add template saving/loading functionality

### Phase 3: Advanced Features

1. Implement `EfficiencyMonitor` with historical tracking
2. Add optimization suggestions
3. Create interactive chain visualization
4. Implement drag-and-drop functionality

### Phase 4: Polish and Integration

1. Apply consistent styling and theming
2. Add animations and transitions
3. Implement responsive design for different screen sizes
4. Integrate with game event system for real-time updates

## Accessibility Considerations

1. **Keyboard Navigation**:

   - All interactive elements should be keyboard accessible
   - Implement logical tab order
   - Add keyboard shortcuts for common actions

2. **Screen Reader Support**:

   - Add proper ARIA labels and roles
   - Ensure meaningful text alternatives for visual elements
   - Implement announcements for state changes

3. **Color Considerations**:
   - Ensure sufficient color contrast
   - Don't rely solely on color to convey information
   - Provide alternative visual indicators (patterns, icons)

## Performance Considerations

1. **Component Optimization**:

   - Use React.memo for components that render frequently
   - Implement virtualization for long lists
   - Use requestAnimationFrame for animations

2. **Data Management**:

   - Implement data caching for converter and recipe information
   - Use efficient data structures for quick lookups
   - Batch updates to minimize render cycles

3. **Rendering Optimization**:
   - Use CSS transitions instead of JS animations where possible
   - Optimize SVG rendering for chain visualizations
   - Implement progressive loading for complex views
