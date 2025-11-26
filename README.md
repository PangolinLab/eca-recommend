## Encryption and Compression Recommendation (ECA-Recommend)

本库是 **PangolinLab** 的推荐算法库，用于推荐加密和压缩算法。

### 加密算法列表

 - AES 256 GCM
 - AES 256 GCM SIV
 - XChaCha20-Poly1305

### 压缩算法列表

- LZ4
- LZMA2
- ZIP
- ZSTD

### 示例代码

```go
package main

import (
	"fmt"
	"github.com/PangolinLab/eca-recommend"
	"os"
)

// --- 示例用法 ---
func main() {
	// 示例
	f, _ := os.Open("example.txt")
	defer f.Close()
	rec, err := eca_recommend.RecommendAlgorithms(f, 48, 0.8, 0, Prefs{Tradeoff: "ratio", AssumeAESNI: true})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("%+v\n", rec)
}

```

### 推荐标准

- 文件本身
- 文件大小
- 多久没用
- 注意力（参考 LFS (目前实现 LFS.FUSE 的 ML 文件预测)）