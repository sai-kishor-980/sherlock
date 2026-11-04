import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Forensic Workstation ErrorBoundary caught:", error, errorInfo);
    this.setState({ errorInfo });
  }

  public handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="forensic-card p-6 border-rose-500/40 bg-rose-950/20 my-4 space-y-4">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-rose-500/20 border border-rose-500/30 text-rose-400">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div className="flex-1">
              <h3 className="text-sm font-bold text-rose-300">
                {this.props.fallbackTitle || "Workstation Render Exception"}
              </h3>
              <p className="text-xs text-slate-300 mt-1">
                A UI component encountered an unexpected error while processing forensic data.
              </p>
              {this.state.error && (
                <div className="mt-3 p-3 rounded bg-dark-900 border border-slate-800 text-[11px] font-mono text-rose-400 overflow-x-auto">
                  {this.state.error.message || String(this.state.error)}
                </div>
              )}
            </div>
          </div>
          <div className="flex items-center gap-3 pt-2">
            <button
              type="button"
              onClick={this.handleReset}
              className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold flex items-center gap-2 transition cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Workstation</span>
            </button>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold transition cursor-pointer"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
