import { Component, type ErrorInfo, type ReactNode } from 'react';
import { de } from '../i18n/de';

// Ohne Fehlergrenze reißt ein einziger Fehler in einem Werkzeug die ganze
// Oberfläche mit: React hängt den Baum aus, und übrig bleibt die
// Hintergrundfarbe. Wer das sieht, weiß nicht, was kaputt ist — und kann es
// auch nicht berichten. Deshalb hier: der Fehler bleibt lokal, und seine
// Meldung steht auf dem Bildschirm statt nur in der Konsole.

interface Props { children: ReactNode; label?: string }
interface State { error: Error | null; info: string | null }

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, info: null };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Die Komponentenspur sagt, WO es geknallt hat — genau das fehlt sonst.
    this.setState({ info: (info.componentStack || '').trim().split('\n').slice(0, 6).join('\n') });
    console.error('A38: Fehler in', this.props.label ?? 'der Ansicht', error, info);
  }

  render(): ReactNode {
    const { error, info } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="fwpt-card space-y-2 border-red-800">
        <h2 className="font-medium text-red-300">{de.errorBoundary.title}</h2>
        <p className="text-sm text-slate-300">
          {de.errorBoundary.hint}
          {this.props.label ? ` (${this.props.label})` : ''}
        </p>
        <pre className="overflow-auto rounded border border-slate-800 bg-slate-950 p-2 text-xs text-red-300">
          {String(error?.message || error)}
        </pre>
        {info && (
          <pre className="max-h-40 overflow-auto rounded border border-slate-800 bg-slate-950 p-2 text-[11px] text-slate-500">
            {info}
          </pre>
        )}
        <button type="button" className="fwpt-btn-ghost"
          onClick={() => this.setState({ error: null, info: null })}>
          {de.errorBoundary.retry}
        </button>
      </div>
    );
  }
}
