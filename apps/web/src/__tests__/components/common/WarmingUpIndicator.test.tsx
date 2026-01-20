/**
 * Tests for WarmingUpIndicator component.
 * Verifies correct display of warming up banner based on health status.
 */

import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { WarmingUpIndicator } from '@/components/common/WarmingUpIndicator';

describe('WarmingUpIndicator', () => {
  it('should render nothing when status is healthy', () => {
    const { container } = render(<WarmingUpIndicator status="healthy" />);
    expect(container.firstChild).toBeNull();
  });

  it('should render warming up message when status is degraded', () => {
    render(<WarmingUpIndicator status="degraded" />);

    expect(screen.getByRole('status')).toBeInTheDocument();
    expect(screen.getByText(/warming up/i)).toBeInTheDocument();
    expect(screen.getByText(/database is starting/i)).toBeInTheDocument();
  });

  it('should render service unavailable message when status is unhealthy', () => {
    render(<WarmingUpIndicator status="unhealthy" show={true} />);

    expect(screen.getByRole('status')).toBeInTheDocument();
    expect(screen.getByText(/service unavailable/i)).toBeInTheDocument();
  });

  it('should render custom message when provided', () => {
    const customMessage = 'Custom warming message';
    render(<WarmingUpIndicator status="degraded" message={customMessage} />);

    expect(screen.getByText(customMessage)).toBeInTheDocument();
  });

  it('should show indicator when show prop is true regardless of status', () => {
    render(<WarmingUpIndicator status="healthy" show={true} message="Forced display" />);

    expect(screen.getByRole('status')).toBeInTheDocument();
    expect(screen.getByText('Forced display')).toBeInTheDocument();
  });

  it('should hide indicator when show prop is false', () => {
    const { container } = render(<WarmingUpIndicator status="degraded" show={false} />);
    expect(container.firstChild).toBeNull();
  });

  it('should have correct test id for E2E testing', () => {
    render(<WarmingUpIndicator status="degraded" />);
    expect(screen.getByTestId('warming-up-indicator')).toBeInTheDocument();
  });

  it('should have correct aria-live attribute for accessibility', () => {
    render(<WarmingUpIndicator status="degraded" />);
    expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite');
  });

  it('should apply yellow styling for degraded status', () => {
    render(<WarmingUpIndicator status="degraded" />);

    const indicator = screen.getByTestId('warming-up-indicator');
    expect(indicator.className).toContain('bg-yellow');
  });

  it('should apply red styling for unhealthy status', () => {
    render(<WarmingUpIndicator status="unhealthy" show={true} />);

    const indicator = screen.getByTestId('warming-up-indicator');
    expect(indicator.className).toContain('bg-red');
  });
});
