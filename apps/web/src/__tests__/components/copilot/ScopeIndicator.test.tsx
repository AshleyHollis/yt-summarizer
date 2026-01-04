/**
 * Tests for ScopeIndicator component
 * 
 * Tests the AI knowledge settings and scope selection controls
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import { ScopeIndicator } from '@/components/copilot/subcomponents/ScopeIndicator';
import React from 'react';

// Mock the providers
const mockUseVideoContext = vi.fn();
const mockUseScope = vi.fn();
const mockUseAISettings = vi.fn();

vi.mock('@/app/providers', () => ({
  useVideoContext: () => mockUseVideoContext(),
  useScope: () => mockUseScope(),
  useAISettings: () => mockUseAISettings(),
}));

describe('ScopeIndicator', () => {
  const defaultScopeContext = {
    scope: {},
    clearScope: vi.fn(),
    setScope: vi.fn(),
  };

  const defaultAISettings = {
    settings: {
      useVideoContext: true,
      useLLMKnowledge: true,
      useWebSearch: false,
    },
    toggleSetting: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseVideoContext.mockReturnValue({ currentVideo: null });
    mockUseScope.mockReturnValue(defaultScopeContext);
    mockUseAISettings.mockReturnValue(defaultAISettings);
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the Search and Include labels', () => {
      render(<ScopeIndicator />);

      expect(screen.getByText('Search:')).toBeInTheDocument();
      expect(screen.getByText('Include:')).toBeInTheDocument();
    });

    it('renders All Videos when no current video context', () => {
      render(<ScopeIndicator />);

      expect(screen.getByText('All Videos')).toBeInTheDocument();
    });

    it('renders all knowledge source toggles', () => {
      render(<ScopeIndicator />);

      expect(screen.getByText('Your Videos')).toBeInTheDocument();
      expect(screen.getByText('AI Knowledge')).toBeInTheDocument();
      expect(screen.getByText('Web Search')).toBeInTheDocument();
    });

    it('renders help button', () => {
      render(<ScopeIndicator />);

      expect(screen.getByTitle('What do these options mean?')).toBeInTheDocument();
    });
  });

  describe('Scope selection with video context', () => {
    const videoContext = {
      currentVideo: {
        videoId: 'video-123',
        title: 'Test Video',
        channelName: 'Test Channel',
        youtubeVideoId: 'dQw4w9WgXcQ',
      },
    };

    it('renders all three scope options when video is selected', () => {
      mockUseVideoContext.mockReturnValue(videoContext);
      
      render(<ScopeIndicator />);

      expect(screen.getByText('All Videos')).toBeInTheDocument();
      expect(screen.getByText('This Channel')).toBeInTheDocument();
      expect(screen.getByText('This Video')).toBeInTheDocument();
    });

    it('calls setScope with channel when This Channel is clicked', () => {
      mockUseVideoContext.mockReturnValue(videoContext);
      
      render(<ScopeIndicator />);

      fireEvent.click(screen.getByText('This Channel'));

      expect(defaultScopeContext.setScope).toHaveBeenCalledWith({
        channels: ['Test Channel'],
      });
    });

    it('calls setScope with videoIds when This Video is clicked', () => {
      mockUseVideoContext.mockReturnValue(videoContext);
      
      render(<ScopeIndicator />);

      fireEvent.click(screen.getByText('This Video'));

      expect(defaultScopeContext.setScope).toHaveBeenCalledWith({
        videoIds: ['video-123'],
      });
    });

    it('calls clearScope when All Videos is clicked from channel scope', () => {
      mockUseVideoContext.mockReturnValue(videoContext);
      mockUseScope.mockReturnValue({
        ...defaultScopeContext,
        scope: { channels: ['Test Channel'] },
      });
      
      render(<ScopeIndicator />);

      fireEvent.click(screen.getByText('All Videos'));

      expect(defaultScopeContext.clearScope).toHaveBeenCalled();
    });
  });

  describe('AI Knowledge Settings toggles', () => {
    it('toggles useVideoContext when Your Videos is clicked', () => {
      render(<ScopeIndicator />);

      fireEvent.click(screen.getByText('Your Videos'));

      expect(defaultAISettings.toggleSetting).toHaveBeenCalledWith('useVideoContext');
    });

    it('toggles useLLMKnowledge when AI Knowledge is clicked', () => {
      render(<ScopeIndicator />);

      fireEvent.click(screen.getByText('AI Knowledge'));

      expect(defaultAISettings.toggleSetting).toHaveBeenCalledWith('useLLMKnowledge');
    });

    it('toggles useWebSearch when Web Search is clicked', () => {
      render(<ScopeIndicator />);

      fireEvent.click(screen.getByText('Web Search'));

      expect(defaultAISettings.toggleSetting).toHaveBeenCalledWith('useWebSearch');
    });

    it('shows active state for enabled settings', () => {
      render(<ScopeIndicator />);

      // useVideoContext and useLLMKnowledge are true, useWebSearch is false
      const yourVideosBtn = screen.getByText('Your Videos').closest('button');
      const aiKnowledgeBtn = screen.getByText('AI Knowledge').closest('button');
      const webSearchBtn = screen.getByText('Web Search').closest('button');

      // Active buttons should have the active class (with bg-primary and text-white)
      expect(yourVideosBtn?.className).toContain('bg-[var(--copilot-kit-primary-color)]');
      expect(yourVideosBtn?.className).toContain('text-white');
      expect(aiKnowledgeBtn?.className).toContain('bg-[var(--copilot-kit-primary-color)]');
      expect(aiKnowledgeBtn?.className).toContain('text-white');
      // Inactive button should have muted color
      expect(webSearchBtn?.className).toContain('text-[var(--copilot-kit-muted-color)]');
    });

    it('shows inactive state for disabled settings', () => {
      mockUseAISettings.mockReturnValue({
        settings: {
          useVideoContext: false,
          useLLMKnowledge: false,
          useWebSearch: true,
        },
        toggleSetting: vi.fn(),
      });

      render(<ScopeIndicator />);

      const yourVideosBtn = screen.getByText('Your Videos').closest('button');
      const aiKnowledgeBtn = screen.getByText('AI Knowledge').closest('button');
      const webSearchBtn = screen.getByText('Web Search').closest('button');

      // Inactive buttons should have muted color
      expect(yourVideosBtn?.className).toContain('text-[var(--copilot-kit-muted-color)]');
      expect(aiKnowledgeBtn?.className).toContain('text-[var(--copilot-kit-muted-color)]');
      // Active button should have primary color bg and white text
      expect(webSearchBtn?.className).toContain('bg-[var(--copilot-kit-primary-color)]');
      expect(webSearchBtn?.className).toContain('text-white');
    });
  });

  describe('Help panel', () => {
    it('shows help panel when help button is clicked', () => {
      render(<ScopeIndicator />);

      // Help panel should not be visible initially
      expect(screen.queryByText('How to customize AI responses:')).not.toBeInTheDocument();

      // Click help button
      fireEvent.click(screen.getByTitle('What do these options mean?'));

      // Help panel should be visible
      expect(screen.getByText('How to customize AI responses:')).toBeInTheDocument();
    });

    it('hides help panel when Got it button is clicked', () => {
      render(<ScopeIndicator />);

      // Open help panel
      fireEvent.click(screen.getByTitle('What do these options mean?'));
      expect(screen.getByText('How to customize AI responses:')).toBeInTheDocument();

      // Click "Got it" button
      fireEvent.click(screen.getByText('Got it'));

      // Help panel should be hidden
      expect(screen.queryByText('How to customize AI responses:')).not.toBeInTheDocument();
    });

    it('help panel contains explanations for all options', () => {
      render(<ScopeIndicator />);

      // Open help panel
      fireEvent.click(screen.getByTitle('What do these options mean?'));

      // Check for key explanations
      expect(screen.getByText(/Choose which videos to search/)).toBeInTheDocument();
      expect(screen.getByText(/Transcripts and summaries from your library/)).toBeInTheDocument();
      expect(screen.getByText(/general training knowledge/)).toBeInTheDocument();
      expect(screen.getByText(/Live search results from the internet/)).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('all buttons have appropriate titles', () => {
      mockUseVideoContext.mockReturnValue({
        currentVideo: {
          videoId: 'video-123',
          title: 'Test Video',
          channelName: 'Test Channel',
        },
      });

      render(<ScopeIndicator />);

      // Scope buttons should have descriptive titles
      expect(screen.getByTitle('Search your entire library')).toBeInTheDocument();
      expect(screen.getByTitle(/Only Test Channel/)).toBeInTheDocument();
      expect(screen.getByTitle('Only the current video')).toBeInTheDocument();
    });

    it('knowledge source buttons have enable/disable context in titles', () => {
      render(<ScopeIndicator />);

      // Active settings show "Disable" in title
      expect(screen.getByTitle(/Disable.*Search transcripts/)).toBeInTheDocument();
      expect(screen.getByTitle(/Disable.*general knowledge/)).toBeInTheDocument();
      
      // Inactive setting shows "Enable" in title
      expect(screen.getByTitle(/Enable.*Search the web/)).toBeInTheDocument();
    });
  });
});
