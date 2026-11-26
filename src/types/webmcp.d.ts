export interface WebMcpToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface WebMcpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: WebMcpToolAnnotations;
  execute: (input: Record<string, unknown>, client?: unknown) => Promise<unknown> | unknown;
}

export interface WebMcpModelContext {
  registerTool?: (tool: WebMcpToolDefinition) => void;
  unregisterTool?: (name: string) => void;
  provideContext?: (context: { tools: WebMcpToolDefinition[] }) => void;
  clearContext?: () => void;
}

declare global {
  interface Navigator {
    modelContext?: WebMcpModelContext;
  }
}

declare module "react" {
  interface FormHTMLAttributes<T> {
    toolname?: string;
    tooldescription?: string;
    toolautosubmit?: string | boolean;
  }
  interface InputHTMLAttributes<T> {
    toolparamtitle?: string;
    toolparamdescription?: string;
  }
}
