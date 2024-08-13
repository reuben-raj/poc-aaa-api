import {Logger} from '@aws-lambda-powertools/logger';

let logger: Logger;

export function initLogger(serviceName: string) {
    if (!logger) logger = new Logger({serviceName});
}

export function getLogger() {
    return logger;
}
