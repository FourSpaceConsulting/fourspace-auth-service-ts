import { DateProvider } from '../date-provider';

import moment from 'moment';

export class DateProviderSystem implements DateProvider {
    getDateTime(): Date {
        return moment.utc().toDate();
    }
}
