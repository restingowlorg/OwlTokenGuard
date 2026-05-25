export interface ILogger {
  debug(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

export class DefaultLogger implements ILogger {
  constructor(private readonly enabled: boolean = false) {}

  debug(message: string, ...args: unknown[]): void {
    if (this.enabled) console.debug(message, ...args);
  }

  error(message: string, ...args: unknown[]): void {
    console.error(message, ...args);
  }
}
