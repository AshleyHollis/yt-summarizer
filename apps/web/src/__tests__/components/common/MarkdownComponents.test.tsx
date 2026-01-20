import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import {
  MarkdownRenderer,
  PROSE_CLASSES,
  PROSE_VARIANTS,
} from '@/components/common/MarkdownRenderer';
import { CollapsibleContent } from '@/components/common/CollapsibleContent';

describe('MarkdownRenderer', () => {
  it('renders markdown content', () => {
    render(<MarkdownRenderer content="**Hello** world" />);
    expect(screen.getByText('Hello')).toBeInTheDocument();
    expect(screen.getByText('world')).toBeInTheDocument();
  });

  it('applies default prose classes', () => {
    const { container } = render(<MarkdownRenderer content="Test" />);
    const article = container.querySelector('article');
    expect(article).toBeInTheDocument();
    expect(article).toHaveClass('prose');
  });

  it('renders with purple variant', () => {
    const { container } = render(<MarkdownRenderer content="Test" variant="summary" />);
    const article = container.querySelector('article');
    expect(article).toHaveClass('prose');
  });

  it('accepts additional className', () => {
    const { container } = render(<MarkdownRenderer content="Test" className="custom-class" />);
    const article = container.querySelector('article');
    expect(article).toHaveClass('custom-class');
  });

  it('exports PROSE_CLASSES constant', () => {
    expect(PROSE_CLASSES).toContain('prose');
    expect(PROSE_CLASSES).toContain('dark:prose-invert');
  });

  it('exports PROSE_VARIANTS', () => {
    expect(PROSE_VARIANTS).toHaveProperty('default');
    expect(PROSE_VARIANTS).toHaveProperty('compact');
    expect(PROSE_VARIANTS).toHaveProperty('summary');
  });
});

describe('CollapsibleContent', () => {
  beforeEach(() => {
    // Mock scrollHeight for testing collapse detection
    Object.defineProperty(HTMLElement.prototype, 'scrollHeight', {
      configurable: true,
      get() {
        // Return a height larger than default collapsed height
        return 400;
      },
    });
  });

  it('renders children', () => {
    render(
      <CollapsibleContent>
        <p>Test content</p>
      </CollapsibleContent>
    );
    expect(screen.getByText('Test content')).toBeInTheDocument();
  });

  it('shows expand button when content exceeds collapsed height', () => {
    render(
      <CollapsibleContent collapsedHeight={100}>
        <p>This is a long text that should exceed the collapsed height</p>
      </CollapsibleContent>
    );
    expect(screen.getByText('Show more')).toBeInTheDocument();
  });

  it('toggles expand/collapse on button click', async () => {
    render(
      <CollapsibleContent collapsedHeight={100}>
        <p>Test content</p>
      </CollapsibleContent>
    );

    const button = screen.getByText('Show more');
    fireEvent.click(button);
    expect(screen.getByText('Show less')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Show less'));
    expect(screen.getByText('Show more')).toBeInTheDocument();
  });

  it('respects defaultExpanded prop', () => {
    render(
      <CollapsibleContent collapsedHeight={100} defaultExpanded={true}>
        <p>Test content</p>
      </CollapsibleContent>
    );
    expect(screen.getByText('Show less')).toBeInTheDocument();
  });

  it('uses custom expand/collapse labels', () => {
    render(
      <CollapsibleContent collapsedHeight={100} expandLabel="Read more" collapseLabel="Read less">
        <p>Test content</p>
      </CollapsibleContent>
    );
    expect(screen.getByText('Read more')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Read more'));
    expect(screen.getByText('Read less')).toBeInTheDocument();
  });

  it('applies custom className', () => {
    const { container } = render(
      <CollapsibleContent className="my-custom-class">
        <p>Test</p>
      </CollapsibleContent>
    );
    expect(container.querySelector('.my-custom-class')).toBeInTheDocument();
  });
});
