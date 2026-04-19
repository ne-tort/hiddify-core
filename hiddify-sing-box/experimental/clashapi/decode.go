package clashapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const maxAPIBodySize = 256 * 1024

func decodeJSONBody(w http.ResponseWriter, r *http.Request, target any, strict bool) error {
	body := http.MaxBytesReader(w, r.Body, maxAPIBodySize)
	decoder := json.NewDecoder(body)
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(struct{})); err != nil && !errors.Is(err, io.EOF) {
		return errors.New("request body must contain only one JSON object")
	}
	return nil
}
