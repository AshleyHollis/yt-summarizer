'use client';

interface DateRangePickerProps {
  fromDate: string | null;
  toDate: string | null;
  onFromDateChange: (date: string | null) => void;
  onToDateChange: (date: string | null) => void;
}

/**
 * Date range picker for filtering videos by publish date
 */
export function DateRangePicker({
  fromDate,
  toDate,
  onFromDateChange,
  onToDateChange,
}: DateRangePickerProps) {
  return (
    <div className="mb-4">
      <label className="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
        Date Range
      </label>
      <div className="space-y-2">
        <div>
          <label
            htmlFor="from-date"
            className="mb-1 block text-xs text-gray-600 dark:text-gray-300"
          >
            From
          </label>
          <input
            type="date"
            id="from-date"
            value={fromDate || ''}
            onChange={(e) => onFromDateChange(e.target.value || null)}
            className="block w-full rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-800/50 px-3 py-2.5 text-sm text-gray-900 dark:text-gray-100 shadow-sm transition-all hover:border-red-400 focus:border-red-400 focus:bg-white dark:focus:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-red-100 dark:focus:ring-red-900/30"
          />
        </div>
        <div>
          <label htmlFor="to-date" className="mb-1 block text-xs text-gray-600 dark:text-gray-300">
            To
          </label>
          <input
            type="date"
            id="to-date"
            value={toDate || ''}
            onChange={(e) => onToDateChange(e.target.value || null)}
            className="block w-full rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-800/50 px-3 py-2.5 text-sm text-gray-900 dark:text-gray-100 shadow-sm transition-all hover:border-red-400 focus:border-red-400 focus:bg-white dark:focus:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-red-100 dark:focus:ring-red-900/30"
          />
        </div>
      </div>
      {(fromDate || toDate) && (
        <button
          type="button"
          onClick={() => {
            onFromDateChange(null);
            onToDateChange(null);
          }}
          className="mt-2 text-xs text-red-500 hover:text-red-400 transition-colors"
        >
          Clear dates
        </button>
      )}
    </div>
  );
}

export default DateRangePicker;
