package main

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"unicode/utf8"
)

const sharedTextLimit = 1024 * 1024

func (app *application) sharedText(w http.ResponseWriter, r *http.Request) {
	slot := r.PathValue("slot")
	if slot != "a" && slot != "b" {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(app.cfg.dataDir, "text-"+slot+".txt")
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		data, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fail(w, http.StatusInternalServerError, "读取失败")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != app.cfg.publicURL {
		fail(w, http.StatusForbidden, "请求来源无效")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "text/plain" {
		fail(w, http.StatusUnsupportedMediaType, "只支持纯文本")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, sharedTextLimit))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		fail(w, http.StatusRequestEntityTooLarge, "每个文本框最多 1 MB")
	case err != nil || !utf8.Valid(data):
		fail(w, http.StatusBadRequest, "无法读取 UTF-8 文本")
	case atomicFile(path, data) != nil:
		fail(w, http.StatusInternalServerError, "保存失败")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
