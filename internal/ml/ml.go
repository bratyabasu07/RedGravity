package ml

import (
	"fmt"
	"redgravity/internal/cve"
	"redgravity/internal/scoring"
)

// MLPredictor provides ML-based predictions (placeholder for TensorFlow Lite)
type MLPredictor struct {
	Enabled   bool
	ModelPath string
}

// NewMLPredictor creates a new ML predictor
func NewMLPredictor(enabled bool, modelPath string) *MLPredictor {
	return &MLPredictor{
		Enabled:   enabled,
		ModelPath: modelPath,
	}
}

// PredictVulnerability predicts vulnerability likelihood
func (ml *MLPredictor) PredictVulnerability(score scoring.ConfidenceScore, cves []cve.CVEInfo) (float64, error) {
	if !ml.Enabled {
		// Return basic heuristic when ML is disabled
		return ml.heuristicPrediction(score, cves), nil
	}

	// TODO: Implement TensorFlow Lite model inference
	fmt.Println("[ML] ML prediction not yet implemented, using heuristic")
	return ml.heuristicPrediction(score, cves), nil
}

// heuristicPrediction provides rule-based prediction
func (ml *MLPredictor) heuristicPrediction(score scoring.ConfidenceScore, cves []cve.CVEInfo) float64 {
	// Simple heuristic based on CVSS and confidence
	baseScore := float64(score.TotalScore) / 100.0
	cvssWeight := score.HighestCVSS / 10.0

	// Weighted average
	prediction := (baseScore * 0.4) + (cvssWeight * 0.6)

	return prediction
}

// ClassifyRisk classifies risk level
func (ml *MLPredictor) ClassifyRisk(prediction float64) string {
	if prediction >= 0.9 {
		return "CRITICAL"
	} else if prediction >= 0.7 {
		return "HIGH"
	} else if prediction >= 0.4 {
		return "MEDIUM"
	}
	return "LOW"
}
