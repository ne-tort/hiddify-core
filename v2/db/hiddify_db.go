package db

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb/opt"
	tmdb "github.com/tendermint/tm-db"
)

// dataDir is the parent of "{name}.db" LevelDB directories. Overridable in tests.
var dataDir = "data"

// bloatedFileThreshold: more SST/manifest files than this triggers a one-shot compact on open.
const bloatedFileThreshold = 64

const (
	openRetryAttempts = 20
	openRetryDelay    = 50 * time.Millisecond
)

type openDB struct {
	db tmdb.DB
}

var (
	dbMu  sync.Mutex
	dbMap = map[string]*openDB{}
)

// SetDataDir overrides the LevelDB parent directory (tests). Empty resets to "data".
func SetDataDir(dir string) {
	dbMu.Lock()
	defer dbMu.Unlock()
	_ = closeAllLocked(false)
	if dir == "" {
		dataDir = "data"
	} else {
		dataDir = dir
	}
}

// getDB returns a process-wide singleton LevelDB for the table name.
// Must not Close after each op — that aborts compaction and piles up .ldb files.
func getDB(name string) (tmdb.DB, error) {
	dbMu.Lock()
	defer dbMu.Unlock()
	if e, ok := dbMap[name]; ok && e.db != nil {
		return e.db, nil
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	db, err := openGoLevelDB(name)
	if err != nil {
		return nil, err
	}
	if count := countDBFiles(name); count > bloatedFileThreshold {
		log.Printf("leveldb %s: bloated (%d files), rewriting", name, count)
		rewritten, rerr := rewriteBloatedDB(name, db)
		if rerr != nil {
			log.Printf("leveldb %s: rewrite failed: %v (falling back to compact)", name, rerr)
			if cerr := forceCompact(db); cerr != nil {
				log.Printf("leveldb %s: compact failed: %v", name, cerr)
			}
		} else {
			db = rewritten
			log.Printf("leveldb %s: rewrite done (%d -> %d files)", name, count, countDBFiles(name))
		}
	}
	dbMap[name] = &openDB{db: db}
	return db, nil
}

func openGoLevelDB(name string) (tmdb.DB, error) {
	var lastErr error
	for i := 0; i < openRetryAttempts; i++ {
		db, err := tmdb.NewGoLevelDBWithOpts(name, dataDir, &opt.Options{})
		if err == nil {
			return db, nil
		}
		lastErr = err
		log.Printf("Failed attempt %d to open leveldb %s: %v", i+1, name, err)
		time.Sleep(openRetryDelay)
	}
	return nil, lastErr
}

func countDBFiles(name string) int {
	dir := filepath.Join(dataDir, name+".db")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			n++
		}
	}
	return n
}

func forceCompact(d tmdb.DB) error {
	g, ok := d.(*tmdb.GoLevelDB)
	if !ok {
		return nil
	}
	return g.ForceCompact(nil, nil)
}

// rewriteBloatedDB copies all live keys into a fresh LevelDB directory.
// CompactRange alone often fails to reclaim tens of thousands of aborted L0 SSTs
// left by the old open/write/close cycle; a full rewrite always does.
func rewriteBloatedDB(name string, old tmdb.DB) (tmdb.DB, error) {
	type kv struct{ k, v []byte }
	var pairs []kv
	iter, err := old.Iterator(nil, nil)
	if err != nil {
		return nil, err
	}
	for ; iter.Valid(); iter.Next() {
		k := append([]byte(nil), iter.Key()...)
		v := append([]byte(nil), iter.Value()...)
		pairs = append(pairs, kv{k: k, v: v})
	}
	iter.Close()
	_ = old.Close()

	dir := filepath.Join(dataDir, name+".db")
	bak := dir + ".bloated-bak"
	_ = os.RemoveAll(bak)
	if err := os.Rename(dir, bak); err != nil {
		// Re-open original so caller is not left without a DB.
		reopened, oerr := openGoLevelDB(name)
		if oerr != nil {
			return nil, fmt.Errorf("rename bloated db: %w (reopen: %v)", err, oerr)
		}
		return reopened, fmt.Errorf("rename bloated db: %w", err)
	}

	fresh, err := openGoLevelDB(name)
	if err != nil {
		_ = os.RemoveAll(dir)
		_ = os.Rename(bak, dir)
		reopened, oerr := openGoLevelDB(name)
		if oerr != nil {
			return nil, fmt.Errorf("open fresh after rename: %w (restore reopen: %v)", err, oerr)
		}
		return reopened, err
	}
	for _, p := range pairs {
		if err := fresh.Set(p.k, p.v); err != nil {
			_ = fresh.Close()
			_ = os.RemoveAll(dir)
			_ = os.Rename(bak, dir)
			return nil, err
		}
	}
	_ = os.RemoveAll(bak)
	return fresh, nil
}

// CloseAll compacts (best-effort) and closes every open table DB.
func CloseAll() error {
	dbMu.Lock()
	defer dbMu.Unlock()
	return closeAllLocked(true)
}

func closeAllLocked(compact bool) error {
	var first error
	for name, e := range dbMap {
		if e == nil || e.db == nil {
			continue
		}
		if compact {
			if err := forceCompact(e.db); err != nil && first == nil {
				first = err
				log.Printf("leveldb %s: compact on close: %v", name, err)
			}
		}
		if err := e.db.Close(); err != nil && first == nil {
			first = err
		}
	}
	dbMap = map[string]*openDB{}
	return first
}

// GetTable returns a new Table instance for the generic type T, ensuring the struct has an "Id" field.
func GetTable[T any]() *Table[T] {
	var t T
	typeName := reflect.TypeOf(t).Name()
	if !hasIdField(t) {
		panic(fmt.Sprintf("Table %s must have a field named 'Id'", typeName))
	}
	return &Table[T]{name: typeName}
}

func hasIdField[T any](t T) bool {
	val := reflect.Indirect(reflect.ValueOf(t))
	if val.Kind() != reflect.Struct {
		return false
	}
	return val.FieldByName("Id").IsValid()
}

func getIdBytes(id any) []byte {
	res, err := SerializeKey(id)
	if err != nil {
		return nil
	}
	return res
}

func getId[T any](t T) any {
	val := reflect.Indirect(reflect.ValueOf(t))
	if val.Kind() != reflect.Struct {
		return nil
	}
	field := val.FieldByName("Id")
	if field.IsValid() {
		return field.Interface()
	}
	return nil
}

// Table represents a database table for generic type T.
type Table[T any] struct {
	name string
}

// All retrieves all entries from the database and unmarshals them into a slice of T.
func (tbl *Table[T]) All() ([]*T, error) {
	d, err := getDB(tbl.name)
	if d == nil {
		return nil, fmt.Errorf("failed to open database %s, error: %w", tbl.name, err)
	}

	var items []*T
	iter, err := d.Iterator(nil, nil)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		item, err := Deserialize[T](iter.Value())
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func Serialize(data any) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(data)
	return buf.Bytes(), err
}

func SerializeKey(data any) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(data)
	return buf.Bytes(), err
}

func Deserialize[T any](data []byte) (*T, error) {
	var obj T
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&obj)
	return &obj, err
}

// UpdateInsert inserts or updates multiple items in the database.
func (tbl *Table[T]) UpdateInsert(items ...*T) error {
	d, err := getDB(tbl.name)
	if d == nil {
		return fmt.Errorf("failed to open database %s, error: %w", tbl.name, err)
	}

	for _, item := range items {
		b, err := Serialize(item)
		if err != nil {
			return err
		}
		if err := d.Set(getIdBytes(getId(item)), b); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes entries by their IDs.
func (tbl *Table[T]) Delete(ids ...any) error {
	d, err := getDB(tbl.name)
	if d == nil {
		return fmt.Errorf("failed to open database %s, error: %w", tbl.name, err)
	}

	for _, id := range ids {
		if err := d.Delete(getIdBytes(id)); err != nil {
			return err
		}
	}
	return nil
}

// Get retrieves a single item by its ID.
func (tbl *Table[T]) Get(id any) (*T, error) {
	d, err := getDB(tbl.name)
	if d == nil {
		return nil, fmt.Errorf("failed to open database %s, error: %w", tbl.name, err)
	}

	b, err := d.Get(getIdBytes(id))
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("not found")
	}
	return Deserialize[T](b)
}
