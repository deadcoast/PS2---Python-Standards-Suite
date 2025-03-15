# SYSTEM INTEGRATION FILE

## PROPERLY UTILIZING THE ARCHITECTURE DOCUMENTATION

This file documents the current state of the Galactic Sprawl system architecture. It serves as a comprehensive reference for all system components, their relationships, and implementation status. When analyzing the codebase, refer to this document to understand the intended architecture, identify gaps between the current implementation and the architectural vision, and determine what connections need to be established or fixed. This document represents the "source of truth" for system architecture decisions and should inform all implementation work.

## USAGE INSTRUCTIONS FOR IMPLEMENTATION

When working with this architectural documentation:

1. Reference specific components using their unique identifiers to ensure precise communication about system elements
2. Parse all JSON objects and TypeScript interfaces as structured specifications that define the intended implementation
3. When implementing a component, first analyze the relevant codebase files to understand current implementation status
4. Fill in any placeholder values in the interfaces with concrete code implementations that align with architectural standards
5. Present implementation suggestions with specific code examples that follow the architectural patterns
6. Generate actionable code that fulfills the requirements specified in each component section

## IMPLEMENTATION APPROACH

When suggesting implementations based on this document:

1. First identify the component and its connections in the architecture specification
2. Reference the implementation status to understand what needs to be built or modified
3. Follow the specified connection patterns when implementing component relationships
4. Ensure new code aligns with the architectural patterns defined in the document
5. Address any identified issues or missing connections with solutions that conform to the architecture

This approach ensures that all implementation work contributes to a cohesive system that matches the intended architecture while addressing the current state of the codebase.

## 1. SYSTEM ARCHITECTURE OVERVIEW

```json
{
  "system_name": "Galactic Sprawl",
  "architecture_type": "Layered with Event-Driven Communication",
  "primary_patterns": ["Context-Manager Pattern", "Event Bus Pattern", "Integration Layer Pattern"],
  "layer_structure": [
    {
      "layer_id": "ui_layer",
      "name": "UI Layer",
      "components": ["UIComponents", "ContextProviders"]
    },
    {
      "layer_id": "service_layer",
      "name": "Service Layer",
      "components": ["ManagerServices", "IntegrationLayer", "EventBuses"]
    },
    {
      "layer_id": "optimization_layer",
      "name": "Optimization Layer",
      "components": ["ResourceFlowManager", "GameLoop"]
    }
  ]
}
```

## 2. COMPONENT CATALOG

```typescript
interface SystemComponent {
  id: string;
  category: ComponentCategory;
  primary_connections: string[];
  responsibilities: string[];
  implementation_status: "complete" | "partial" | "missing";
}

type ComponentCategory = 
  "UIComponent" | 
  "ContextProvider" | 
  "ManagerService" | 
  "CustomHook" | 
  "IntegrationLayer" | 
  "EventBus";

const ComponentCatalog: SystemComponent[] = [
  // UI Components
  {
    id: "GameHUD",
    category: "UIComponent",
    primary_connections: ["GameContext", "ModuleContext"],
    responsibilities: ["Display game state", "Trigger module building", "Update game state"],
    implementation_status: "partial"
  },
  {
    id: "ResourceVisual",
    category: "UIComponent",
    primary_connections: ["GameContext", "ResourceRatesContext", "ThresholdContext"],
    responsibilities: ["Display resource data", "Show production/consumption rates", "Display threshold alerts"],
    implementation_status: "partial"
  },
  {
    id: "GameStateMonitor",
    category: "UIComponent",
    primary_connections: ["GameContext", "ModuleContext"],
    responsibilities: ["Display real-time rates", "Show module states", "Display system events", "Provide debugging info"],
    implementation_status: "missing"
  },
  
  // Context Providers
  {
    id: "GameContext",
    category: "ContextProvider",
    primary_connections: ["ResourceManager", "SystemIntegration"],
    responsibilities: ["Maintain game state", "Synchronize with manager methods", "Dispatch manager actions"],
    implementation_status: "partial"
  },
  {
    id: "ResourceRatesContext",
    category: "ContextProvider",
    primary_connections: ["ResourceManager", "ThresholdIntegration"],
    responsibilities: ["Track production/consumption rates", "Update on resource events", "Provide data to UI"],
    implementation_status: "partial"
  },
  {
    id: "ThresholdContext",
    category: "ContextProvider",
    primary_connections: ["ResourceManager", "ThresholdIntegration"],
    responsibilities: ["Manage resource thresholds", "Generate alerts", "Trigger production adjustments"],
    implementation_status: "missing"
  },
  {
    id: "ModuleContext",
    category: "ContextProvider",
    primary_connections: ["ModuleManager", "SystemIntegration", "ModuleEventBus"],
    responsibilities: ["Maintain module state", "Synchronize with ModuleManager", "Register for module events"],
    implementation_status: "partial"
  },
  
  // Manager Services
  {
    id: "ResourceManager",
    category: "ManagerService",
    primary_connections: ["ResourceFlowManager", "GameContext", "ModuleManager"],
    responsibilities: ["Manage resources", "Calculate rates", "Process resource transfers"],
    implementation_status: "partial"
  },
  {
    id: "ModuleManager",
    category: "ManagerService",
    primary_connections: ["ModuleContext", "ResourceManager", "ModuleEventBus"],
    responsibilities: ["Manage module lifecycle", "Process module operations", "Emit module events"],
    implementation_status: "partial"
  },
  {
    id: "ExplorationManager",
    category: "ManagerService",
    primary_connections: ["ExplorationSystem"],
    responsibilities: ["Manage exploration", "Process discoveries", "Calculate exploration outcomes"],
    implementation_status: "missing"
  },
  
  // Integration Layer
  {
    id: "SystemIntegration",
    category: "IntegrationLayer",
    primary_connections: ["GameContext", "ResourceManager", "ModuleManager"],
    responsibilities: ["Bridge contexts and managers", "Synchronize states", "Broadcast state changes", "Handle initialization"],
    implementation_status: "partial"
  },
  {
    id: "ThresholdIntegration",
    category: "IntegrationLayer",
    primary_connections: ["ThresholdContext", "ResourceManager"],
    responsibilities: ["Connect threshold and resources", "Update threshold values", "Trigger threshold actions", "Generate alerts"],
    implementation_status: "missing"
  },
  {
    id: "EventBatcher",
    category: "IntegrationLayer",
    primary_connections: ["ModuleEventBus", "GameEventBus", "ResourceEventBus"],
    responsibilities: ["Batch events", "Distribute to appropriate buses", "Process event priorities"],
    implementation_status: "partial"
  },
  
  // Event Buses
  {
    id: "ModuleEventBus",
    category: "EventBus",
    primary_connections: ["ModuleManager", "ModuleContext", "EventDispatcherProvider"],
    responsibilities: ["Handle module events", "Manage subscriptions", "Maintain event history"],
    implementation_status: "partial"
  },
  {
    id: "GameEventBus",
    category: "EventBus",
    primary_connections: ["GameContext", "EventDispatcherProvider"],
    responsibilities: ["Handle game events", "Manage subscriptions", "Maintain event history"],
    implementation_status: "partial"
  },
  {
    id: "ResourceEventBus",
    category: "EventBus",
    primary_connections: ["ResourceManager", "ResourceRatesContext", "EventDispatcherProvider"],
    responsibilities: ["Handle resource events", "Manage subscriptions", "Maintain event history"],
    implementation_status: "partial"
  }
];
```

## 3. CONNECTION MAP

```typescript
interface SystemConnection {
  source_id: string;
  target_id: string;
  connection_type: ConnectionType;
  data_flow: DataFlow;
  implementation_status: "implemented" | "partial" | "missing";
  connection_pattern: string;
}

type ConnectionType = "context-manager" | "ui-context" | "integration" | "event";
type DataFlow = "unidirectional" | "bidirectional";

const ConnectionMap: SystemConnection[] = [
  // UI → Context connections
  {
    source_id: "GameHUD",
    target_id: "GameContext",
    connection_type: "ui-context",
    data_flow: "bidirectional",
    implementation_status: "partial",
    connection_pattern: "useGame() hook"
  },
  {
    source_id: "GameHUD",
    target_id: "ModuleContext",
    connection_type: "ui-context",
    data_flow: "bidirectional",
    implementation_status: "partial",
    connection_pattern: "useModules() hook"
  },
  {
    source_id: "ResourceVisual",
    target_id: "GameContext",
    connection_type: "ui-context",
    data_flow: "bidirectional",
    implementation_status: "partial",
    connection_pattern: "useGame() hook"
  },
  {
    source_id: "ResourceVisual",
    target_id: "ResourceRatesContext",
    connection_type: "ui-context",
    data_flow: "unidirectional",
    implementation_status: "missing",
    connection_pattern: "useResourceRates() hook"
  },
  
  // Context → Manager connections
  {
    source_id: "GameContext",
    target_id: "ResourceManager",
    connection_type: "context-manager",
    data_flow: "bidirectional",
    implementation_status: "partial",
    connection_pattern: "SystemIntegration middleware"
  },
  {
    source_id: "ModuleContext",
    target_id: "ModuleManager",
    connection_type: "context-manager",
    data_flow: "bidirectional",
    implementation_status: "partial",
    connection_pattern: "SystemIntegration middleware"
  },
  {
    source_id: "ThresholdContext",
    target_id: "ResourceManager",
    connection_type: "context-manager",
    data_flow: "bidirectional",
    implementation_status: "missing",
    connection_pattern: "ThresholdIntegration middleware"
  },
  
  // Integration Layer connections
  {
    source_id: "SystemIntegration",
    target_id: "GameContext",
    connection_type: "integration",
    data_flow: "bidirectional",
    implementation_status: "partial",
    connection_pattern: "Context initialization and state sync"
  },
  {
    source_id: "SystemIntegration",
    target_id: "ResourceManager",
    connection_type: "integration",
    data_flow: "bidirectional",
    implementation_status: "partial",
    connection_pattern: "Manager method calls and event subscription"
  },
  {
    source_id: "ThresholdIntegration",
    target_id: "ThresholdContext",
    connection_type: "integration",
    data_flow: "bidirectional",
    implementation_status: "missing",
    connection_pattern: "Context initialization and state sync"
  },
  
  // Event System connections
  {
    source_id: "ModuleManager",
    target_id: "ModuleEventBus",
    connection_type: "event",
    data_flow: "unidirectional",
    implementation_status: "partial",
    connection_pattern: "Event emission"
  },
  {
    source_id: "ResourceManager",
    target_id: "ResourceEventBus",
    connection_type: "event",
    data_flow: "unidirectional",
    implementation_status: "partial",
    connection_pattern: "Event emission"
  },
  {
    source_id: "EventDispatcherProvider",
    target_id: "ModuleEventBus",
    connection_type: "event",
    data_flow: "bidirectional",
    implementation_status: "partial",
    connection_pattern: "React context wrapper"
  }
]
```

## 4. RESOURCE FLOW SYSTEM

```typescript
interface ResourceSystem {
  component_id: string;
  node_types: string[];
  primary_processes: Process[];
  performance_optimizations: Optimization[];
}

interface Process {
  id: string;
  steps: string[];
  implementation_status: "implemented" | "partial" | "missing";
}

interface Optimization {
  id: string;
  strategy: string;
  implementation_status: "implemented" | "partial" | "missing";
}

const ResourceFlowSystem: ResourceSystem = {
  component_id: "ResourceFlowManager",
  node_types: ["ProducerNode", "StorageNode", "ConsumerNode", "ConverterNode"],
  primary_processes: [
    {
      id: "node_management",
      steps: [
        "Register and unregister resource nodes",
        "Track node state and capabilities",
        "Manage node connections and relationships"
      ],
      implementation_status: "partial"
    },
    {
      id: "connection_management",
      steps: [
        "Establish connections between nodes",
        "Control flow rates between connected nodes",
        "Validate connection compatibility"
      ],
      implementation_status: "partial"
    },
    {
      id: "resource_optimization",
      steps: [
        "Calculate optimal flow distributions",
        "Identify resource bottlenecks",
        "Apply efficiency modifiers for converters",
        "Prioritize essential resource consumers"
      ],
      implementation_status: "partial"
    },
    {
      id: "flow_optimization",
      steps: [
        "Register resource nodes with manager",
        "Establish connections between compatible nodes",
        "Process converters to apply efficiency modifiers",
        "Calculate resource availability from producers and storage",
        "Calculate resource demand from consumers",
        "Identify bottlenecks and underutilized resources",
        "Optimize flow rates based on priorities",
        "Generate transfer records"
      ],
      implementation_status: "partial"
    },
    {
      id: "converter_processing",
      steps: [
        "Apply efficiency ratings to resource production",
        "Process converters before other nodes",
        "Modify output connection rates by efficiency factor",
        "Enable simple and complex conversion chains"
      ],
      implementation_status: "missing"
    }
  ],
  performance_optimizations: [
    {
      id: "batch_processing",
      strategy: "Process large networks in batches to avoid blocking the main thread",
      implementation_status: "missing"
    },
    {
      id: "state_caching",
      strategy: "Cache resource states with configurable TTL (time-to-live)",
      implementation_status: "missing"
    },
    {
      id: "incremental_updates",
      strategy: "Update only connections that have changed, not the entire network",
      implementation_status: "partial"
    },
    {
      id: "history_management",
      strategy: "Limit transfer history size to prevent memory issues",
      implementation_status: "missing"
    }
  ]
}
```

## 5. EVENT SYSTEM

```typescript
interface EventSystem {
  component_id: string;
  core_components: EventComponent[];
  subscription_flow: string[];
  react_integration_pattern: string[];
}

interface EventComponent {
  id: string;
  responsibilities: string[];
  implementation_status: "implemented" | "partial" | "missing";
}

const EventSystem: EventSystem = {
  component_id: "ModuleEventBus",
  core_components: [
    {
      id: "ModuleEventBus",
      responsibilities: [
        "Manage event subscription, emission, and history",
        "Operate as a singleton service",
        "Provide subscription management with cleanup",
        "Distribute events to registered listeners",
        "Maintain event history with filtering"
      ],
      implementation_status: "partial"
    },
    {
      id: "EventDispatcherProvider",
      responsibilities: [
        "Wrap ModuleEventBus in a React context",
        "Manage component lifecycle for subscriptions",
        "Provide specialized hooks for components",
        "Track latest events by type"
      ],
      implementation_status: "partial"
    }
  ],
  subscription_flow: [
    "Components or modules subscribe to specific event types",
    "Event source emits event through ModuleEventBus",
    "ModuleEventBus adds event to history",
    "ModuleEventBus notifies all listeners for that event type",
    "Listeners handle event, potentially causing UI updates",
    "React components use hooks to subscribe with automatic cleanup"
  ],
  react_integration_pattern: [
    "Initialize with ModuleEventBus",
    "Subscribe to all event types to track latest events",
    "Provide useEventSubscription hook",
    "Provide useLatestEvent hook",
    "Provide useFilteredEvents hook",
    "Manage subscription cleanup on unmount"
  ]
}
```

## 6. CURRENT ISSUES AND INTEGRATION PRIORITIES

```typescript
interface SystemIntegrationIssues {
  priority_tasks: PriorityTask[];
  current_issues: Issue[];
  missing_connections: MissingConnection[];
  integration_strategy: IntegrationStrategy[];
}

interface PriorityTask {
  id: string;
  description: string;
  components_involved: string[];
  priority: "high" | "medium" | "low";
}

interface Issue {
  id: string;
  description: string;
  impact: string;
  components_affected: string[];
}

interface MissingConnection {
  source_id: string;
  target_id: string;
  connection_description: string;
  implementation_requirements: string[];
}

interface IntegrationStrategy {
  id: string;
  description: string;
  implementation_steps: string[];
}

const SystemIntegrationIssues: SystemIntegrationIssues = {
  priority_tasks: [
    {
      id: "resource_context_connection",
      description: "Connect ResourceManager with GameContext and UI components",
      components_involved: ["ResourceManager", "GameContext", "ResourceVisual"],
      priority: "high"
    },
    {
      id: "module_context_connection",
      description: "Integrate ModuleManager with ModuleContext and module UI components",
      components_involved: ["ModuleManager", "ModuleContext"],
      priority: "high"
    },
    {
      id: "exploration_connection",
      description: "Fix ExplorationManager connections to exploration components",
      components_involved: ["ExplorationManager", "ExplorationSystem"],
      priority: "medium"
    },
    {
      id: "event_registration",
      description: "Ensure all UI components register for relevant events",
      components_involved: ["UIComponents", "EventDispatcherProvider"],
      priority: "high"
    },
    {
      id: "state_update_pattern",
      description: "Create consistent state update patterns throughout the application",
      components_involved: ["ContextProviders", "ManagerServices"],
      priority: "medium"
    }
  ],
  current_issues: [
    {
      id: "missing_game_loop",
      description: "Managers have update() methods but no central game loop coordinating these updates",
      impact: "Manager updates aren't happening on a controlled tick cycle",
      components_affected: ["ResourceManager", "ModuleManager", "ExplorationManager"]
    },
    {
      id: "inconsistent_resource_flow",
      description: "Resources are updated both directly (GameContext dispatches) and through events",
      impact: "No single source of truth for resource changes",
      components_affected: ["ResourceManager", "GameContext", "ResourceEventBus"]
    },
    {
      id: "disconnected_event_system",
      description: "EventBatcher is well-designed but used inconsistently across components",
      impact: "Many UI components don't properly subscribe to the events they need",
      components_affected: ["EventBatcher", "UIComponents", "ContextProviders"]
    },
    {
      id: "initialization_order",
      description: "SystemIntegration depends on resourceManager but gets initialized too late",
      impact: "Components try to use managers before they're ready",
      components_affected: ["SystemIntegration", "ResourceManager", "UIComponents"]
    },
    {
      id: "missing_actions",
      description: "UPDATE_RESOURCE_RATES action mentioned in SystemIntegration doesn't exist in GameContext",
      impact: "No action to handle resource rate updates",
      components_affected: ["GameContext", "SystemIntegration"]
    }
  ],
  missing_connections: [
    {
      source_id: "ResourceManager",
      target_id: "GameContext",
      connection_description: "ResourceManager needs to consistently notify GameContext of changes",
      implementation_requirements: [
        "Consistent notification pattern",
        "Actions for all resource state changes including rates"
      ]
    },
    {
      source_id: "ModuleManager",
      target_id: "ModuleContext",
      connection_description: "ModuleContext operations should consistently go through ModuleManager",
      implementation_requirements: [
        "ModuleContext operations through ModuleManager",
        "Events from ModuleManager update ModuleContext"
      ]
    },
    {
      source_id: "ThresholdContext",
      target_id: "ResourceManager",
      connection_description: "ThresholdContext needs to be updated when resources change",
      implementation_requirements: [
        "Resource change notifications to ThresholdContext",
        "Threshold actions affecting resource usage policies"
      ]
    },
    {
      source_id: "UIComponents",
      target_id: "EventSystem",
      connection_description: "UI components need to consistently subscribe to relevant events",
      implementation_requirements: [
        "Consistent event subscription in UI components",
        "Events triggering state updates through context dispatches"
      ]
    }
  ],
  integration_strategy: [
    {
      id: "game_loop",
      description: "Establishing a Central Game Loop",
      implementation_steps: [
        "Create a GameLoop class to coordinate all manager updates",
        "Implement a consistent tick cycle for predictable state updates",
        "Register managers with the game loop",
        "Implement update priorities for different systems"
      ]
    },
    {
      id: "resource_standardization",
      description: "Standardizing Resource Management",
      implementation_steps: [
        "Designate ResourceManager as the single source of truth for resource changes",
        "Ensure all resource updates flow through a consistent pipeline",
        "Implement resource change tracking and notification",
        "Create standardized resource update events"
      ]
    },
    {
      id: "event_connection",
      description: "Connecting Event Systems",
      implementation_steps: [
        "Standardize event subscription across all UI components",
        "Ensure all managers properly emit events for state changes",
        "Implement event filtering and prioritization",
        "Create consistent event handling patterns"
      ]
    },
    {
      id: "initialization_sequence",
      description: "Fixing Initialization Sequence",
      implementation_steps: [
        "Create a proper dependency graph for initialization",
        "Implement a staged initialization process",
        "Add dependency checking before component initialization",
        "Implement service readiness notifications"
      ]
    },
    {
      id: "context_actions",
      description: "Completing GameContext Actions",
      implementation_steps: [
        "Add missing action types to GameContext",
        "Implement handlers for all required state changes",
        "Create consistent action creator patterns",
        "Document action flow through the system"
      ]
    }
  ]
}
```

## 7. IMPLEMENTATION GUIDANCE FOR AI

When implementing this architecture:

1. **Component Analysis** - First analyze each component to understand its responsibilities and connections.

2. **Connection Implementation** - Focus on implementing missing connections between components following these patterns:
   - UI → Context: Use React hooks
   - Context → Manager: Use middleware pattern
   - Manager → Event: Use event emission pattern
   - Event → UI: Use subscription pattern

3. **System Integration** - Focus first on these critical integration points:
   - ResourceManager → GameContext → ResourceVisual chain
   - ModuleManager → ModuleContext → module UI components
   - Event system subscription for UI components
   - GameLoop integration with manager update methods

4. **Consistent Patterns** - Implement these architectural patterns consistently:
   - State management: Single source of truth with clear update flows
   - Event handling: Consistent subscription and emission patterns
   - Initialization: Proper dependency resolution and readiness checks
   - UI updates: Consistent data flow from managers to UI

5. **Implementation Sequence** - Follow this sequence for implementation:
   1. Core infrastructure (GameLoop, EventSystem)
   2. Manager standardization
   3. Context-Manager connections
   4. UI-Context connections
   5. Performance optimizations

When analyzing code against this architecture, identify structural gaps and implementation inconsistencies, then generate appropriate integration code following the patterns specified in this document.