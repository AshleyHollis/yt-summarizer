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
      <label className="mb-2 block text-sm font-medium text-gray-700">
        Date Range
      </label>
      <div className="space-y-2">
        <div>
          <label
            htmlFor="from-date"
            className="mb-1 block text-xs text-gray-500"
          >
            From
          </label>
          <input
            type="date"
            id="from-date"
            value={fromDate || ''}
            onChange={(e) => onFromDateChange(e.target.value || null)}
            className="block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>
        <div>
          <label htmlFor="to-date" className="mb-1 block text-xs text-gray-500">
            To
          </label>
          <input
            type="date"
            id="to-date"
            value={toDate || ''}
            onChange={(e) => onToDateChange(e.target.value || null)}
            className="block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
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
          className="mt-2 text-xs text-indigo-600 hover:text-indigo-500"
        >
          Clear dates
        </button>
      )}
    </div>
  );
}

export default DateRangePicker;
