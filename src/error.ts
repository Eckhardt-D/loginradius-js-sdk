import type {SDKError} from './auth.types';

export class LibError extends Error implements SDKError {
  constructor(type: string, message: string) {
    super(message);
    this.name = type;
    this.message = message;
  }
}
