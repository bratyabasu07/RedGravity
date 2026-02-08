package core

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// PipelineStage represents a stage in the pipeline
type PipelineStage struct {
	Name    string
	Execute func(ctx context.Context, input interface{}) (interface{}, error)
	Timeout time.Duration
}

// PipelineResult holds the result of a pipeline execution
type PipelineResult struct {
	Stage  string
	Output interface{}
	Error  error
}

// Pipeline orchestrates the execution of multiple stages
type Pipeline struct {
	Stages        []PipelineStage
	MaxRetries    int
	RetryBackoff  time.Duration
	MaxGoroutines int
	GlobalTimeout time.Duration
	Results       []PipelineResult
	mutex         sync.Mutex
}

// NewPipeline creates a new pipeline
func NewPipeline(globalTimeout time.Duration, maxRetries int, retryBackoff time.Duration, maxGoroutines int) *Pipeline {
	return &Pipeline{
		Stages:        make([]PipelineStage, 0),
		MaxRetries:    maxRetries,
		RetryBackoff:  retryBackoff,
		MaxGoroutines: maxGoroutines,
		GlobalTimeout: globalTimeout,
		Results:       make([]PipelineResult, 0),
	}
}

// AddStage adds a stage to the pipeline
func (p *Pipeline) AddStage(name string, execute func(ctx context.Context, input interface{}) (interface{}, error), timeout time.Duration) {
	p.Stages = append(p.Stages, PipelineStage{
		Name:    name,
		Execute: execute,
		Timeout: timeout,
	})
}

// Run executes the pipeline sequentially
func (p *Pipeline) Run(ctx context.Context, initialInput interface{}) error {
	// Create global context with timeout
	globalCtx, cancel := context.WithTimeout(ctx, p.GlobalTimeout)
	defer cancel()

	currentInput := initialInput

	for _, stage := range p.Stages {
		fmt.Printf("[PIPELINE] Executing stage: %s\n", stage.Name)

		// Execute stage with retry
		output, err := p.executeStageWithRetry(globalCtx, stage, currentInput)

		// Store result
		p.mutex.Lock()
		p.Results = append(p.Results, PipelineResult{
			Stage:  stage.Name,
			Output: output,
			Error:  err,
		})
		p.mutex.Unlock()

		if err != nil {
			return fmt.Errorf("stage %s failed: %w", stage.Name, err)
		}

		// Pass output to next stage
		currentInput = output

		// Check if global context is canceled
		select {
		case <-globalCtx.Done():
			return fmt.Errorf("pipeline canceled: %w", globalCtx.Err())
		default:
		}
	}

	fmt.Println("[PIPELINE] All stages completed successfully")
	return nil
}

// executeStageWithRetry executes a stage with exponential backoff retry
func (p *Pipeline) executeStageWithRetry(ctx context.Context, stage PipelineStage, input interface{}) (interface{}, error) {
	var output interface{}
	var err error

	for attempt := 0; attempt < p.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := p.RetryBackoff * time.Duration(1<<uint(attempt-1))
			fmt.Printf("[RETRY] Stage %s failed, retrying in %v (attempt %d/%d)\n",
				stage.Name, backoff, attempt+1, p.MaxRetries)
			time.Sleep(backoff)
		}

		// Create stage context with timeout
		stageCtx, cancel := context.WithTimeout(ctx, stage.Timeout)

		// Execute in goroutine to respect timeout
		done := make(chan bool)
		go func() {
			output, err = stage.Execute(stageCtx, input)
			done <- true
		}()

		// Wait for completion or timeout
		select {
		case <-done:
			cancel()
			if err == nil {
				return output, nil
			}
		case <-stageCtx.Done():
			cancel()
			err = fmt.Errorf("stage timeout exceeded")
		}
	}

	return nil, fmt.Errorf("max retries exceeded: %w", err)
}

// RunParallel executes multiple tasks in parallel with controlled concurrency
func (p *Pipeline) RunParallel(ctx context.Context, tasks []func(ctx context.Context) error) error {
	var wg sync.WaitGroup
	errorChan := make(chan error, len(tasks))
	semaphore := make(chan struct{}, p.MaxGoroutines)

	for i, task := range tasks {
		wg.Add(1)
		go func(index int, fn func(ctx context.Context) error) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fmt.Printf("[PARALLEL] Executing task %d/%d\n", index+1, len(tasks))

			if err := fn(ctx); err != nil {
				errorChan <- fmt.Errorf("task %d failed: %w", index, err)
			}
		}(i, task)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errorChan)

	// Collect errors
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("parallel execution had %d errors: %v", len(errors), errors)
	}

	return nil
}

// GetResults returns all pipeline results
func (p *Pipeline) GetResults() []PipelineResult {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.Results
}

// GetStageResult returns the result of a specific stage
func (p *Pipeline) GetStageResult(stageName string) (interface{}, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for _, result := range p.Results {
		if result.Stage == stageName {
			return result.Output, result.Error
		}
	}

	return nil, fmt.Errorf("stage %s not found", stageName)
}
