package eca_recommend

import (
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Prefs 可选偏好："speed","ratio","balanced"
type Prefs struct {
	Tradeoff       string // "speed"|"ratio"|"balanced"
	AssumeAESNI    bool   // 是否假设有 AES-NI（会偏向 aes-gcm）
	ForceDetectExt bool   // 是否强制使用扩展名优先（默认用扩展名+MIME）
}

// Recommendation 推荐结果
type Recommendation struct {
	Encryption       string             // "aes256gcm"|"aes256gcmsiv"|"xchacha20poly1305"
	Compression      string             // "zip"|"lzma2"|"lz4"|"zstd"|"none"
	ZstdLevel        int                // 推荐 zstd level (if comp == "zstd")
	SkipCompression  bool               // 对高度压缩格式是否建议跳过压缩
	ScoreBreakdown   map[string]float64 // 每个算法得分
	Reason           string
	DetectedMime     string
	DetectedCategory string // "text","image","audio","video","archive","binary"
}

// RecommendAlgorithms 主推荐函数
func RecommendAlgorithms(file *os.File, lastUsedHours int, attention float64, sizeBytes int64, prefs Prefs) (Recommendation, error) {
	var rec Recommendation
	rec.ScoreBreakdown = make(map[string]float64)

	if file == nil {
		return rec, fmt.Errorf("file is nil")
	}

	// 尝试获取 size
	if sizeBytes <= 0 {
		if fi, err := file.Stat(); err == nil {
			sizeBytes = fi.Size()
		} else {
			sizeBytes = 0
		}
	}
	if sizeBytes < 0 {
		sizeBytes = 0
	}

	// 检测类型（扩展名 + DetectContentType）
	mimeStr, category := detectFileCategory(file)
	rec.DetectedMime = mimeStr
	rec.DetectedCategory = category

	// 标准化 tradeoff
	tradeoff := strings.TrimSpace(strings.ToLower(prefs.Tradeoff))
	if tradeoff != "speed" && tradeoff != "ratio" && tradeoff != "balanced" {
		tradeoff = "balanced"
	}

	// clamp attention
	if attention < 0 {
		attention = 0
	} else if attention > 1 {
		attention = 1
	}
	if lastUsedHours < 0 {
		lastUsedHours = 0
	}

	sizeMB := float64(sizeBytes) / (1024.0 * 1024.0)
	luhW := float64(lastUsedHours) / (24.0 * 7.0)
	if luhW > 3 {
		luhW = 3
	}

	// ---------- 加密算法评分 ----------
	encCandidates := []string{"aes256gcm", "aes256gcmsiv", "xchacha20poly1305"}
	encScores := map[string]float64{"aes256gcm": 0, "aes256gcmsiv": 0, "xchacha20poly1305": 0}

	for _, c := range encCandidates {
		score := 0.1
		if c == "aes256gcmsiv" {
			score += attention*2.5 + luhW*1.2
		} else if c == "aes256gcm" {
			if prefs.AssumeAESNI {
				score += attention*0.6 + 2.0
			} else {
				score += attention*0.6 + 0.6
			}
			score += luhW * 0.6
		} else if c == "xchacha20poly1305" {
			if sizeMB > 100 {
				score += 3.0
			}
			if tradeoff == "speed" {
				score += 1.2
			}
			score += attention * 0.8
		}
		encScores[c] = score
		rec.ScoreBreakdown["enc_"+c] = score
	}

	// pick best enc
	bestEnc := ""
	bestEncScore := math.Inf(-1)
	for k, v := range encScores {
		if v > bestEncScore {
			bestEncScore = v
			bestEnc = k
		}
	}
	if bestEnc == "" {
		bestEnc = "aes256gcm"
	}
	rec.Encryption = bestEnc

	// ---------- 压缩算法评分 ----------
	compCandidates := []string{"zip", "lzma2", "lz4", "zstd"}
	compScores := map[string]float64{"zip": 0, "lzma2": 0, "lz4": 0, "zstd": 0}
	isAlreadyCompressed := false
	switch category {
	case "image", "video", "audio", "archive":
		isAlreadyCompressed = true
	}

	for _, c := range compCandidates {
		score := 0.1
		if isAlreadyCompressed {
			if c == "lz4" {
				score += 2.0
			} else {
				score -= 1.2
			}
		} else {
			if c == "lzma2" {
				if tradeoff == "ratio" {
					score += 3.0
				} else if tradeoff == "balanced" {
					score += 1.6
				} else {
					score += 0.6
				}
				if sizeMB > 100 {
					score += 1.2
				}
			} else if c == "zstd" {
				if tradeoff == "ratio" {
					score += 2.5
				} else if tradeoff == "balanced" {
					score += 2.0
				} else {
					score += 1.2
				}
				if sizeMB > 50 {
					score += 1.0
				}
			} else if c == "lz4" {
				if tradeoff == "speed" {
					score += 2.2
				} else if tradeoff == "balanced" {
					score += 1.0
				} else {
					score += 0.3
				}
				if sizeMB < 10 {
					score += 0.6
				}
			} else if c == "zip" {
				if sizeMB < 10 {
					score += 1.2
				}
				if tradeoff == "speed" {
					score += 0.6
				}
			}
		}
		if sizeMB > 500 && (c == "zstd" || c == "lz4") {
			score += 1.2
		}
		compScores[c] = score
		rec.ScoreBreakdown["comp_"+c] = score
	}

	bestComp := ""
	bestCompScore := math.Inf(-1)
	for k, v := range compScores {
		if v > bestCompScore {
			bestCompScore = v
			bestComp = k
		}
	}
	if bestComp == "" {
		bestComp = "lz4"
	}

	// SkipCompression 逻辑
	if isAlreadyCompressed && (bestCompScore < 0.5 || (bestComp == "lz4" && tradeoff != "ratio")) {
		rec.SkipCompression = true
		rec.Compression = "none"
		rec.Reason = fmt.Sprintf("文件类型 %s 可能已经被压缩，建议跳过压缩。", category)
	} else {
		rec.SkipCompression = false
		rec.Compression = bestComp
		rec.Reason = fmt.Sprintf("选中加密: %s（分数 %.2f），压缩: %s（分数 %.2f）", rec.Encryption, bestEncScore, rec.Compression, bestCompScore)
	}

	// zstd level recommendation
	if rec.Compression == "zstd" {
		var level int
		switch tradeoff {
		case "speed":
			level = 1
		case "balanced":
			if sizeMB > 200 {
				level = 3
			} else if sizeMB > 50 {
				level = 5
			} else {
				level = 3
			}
		case "ratio":
			if sizeMB > 500 {
				level = 12
			} else if sizeMB > 200 {
				level = 9
			} else {
				level = 7
			}
		default:
			level = 3
		}
		if level < 1 {
			level = 1
		}
		if level > 22 {
			level = 22
		}
		rec.ZstdLevel = level
	}

	return rec, nil
}

// detectFileCategory returns mime and coarse category
func detectFileCategory(f *os.File) (string, string) {
	buf := make([]byte, 512)
	n, err := f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return "application/octet-stream", "binary"
	}
	sniff := buf[:n]
	mimeStr := http.DetectContentType(sniff)

	ext := strings.ToLower(filepath.Ext(f.Name()))
	if ext != "" {
		if m := mime.TypeByExtension(ext); m != "" {
			mimeStr = m
		}
	}

	low := strings.ToLower(mimeStr)
	category := "binary"
	if strings.HasPrefix(low, "text/") {
		category = "text"
	} else if strings.HasPrefix(low, "image/") {
		category = "image"
	} else if strings.HasPrefix(low, "audio/") {
		category = "audio"
	} else if strings.HasPrefix(low, "video/") {
		category = "video"
	} else if strings.Contains(low, "zip") || strings.Contains(low, "compressed") || strings.Contains(low, "x-rar") || strings.Contains(low, "7z") || strings.Contains(low, "tar") {
		category = "archive"
	} else {
		switch ext {
		case ".txt", ".md", ".csv", ".log", ".json", ".xml", ".yaml", ".yml", ".go", ".py", ".c", ".cpp", ".java":
			category = "text"
		case ".pdf":
			category = "archive"
		}
	}
	return mimeStr, category
}
