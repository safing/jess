// Package supply provides a cache of signets for pre-generating signets.
package supply

import (
	"sync"

	"github.com/safing/jess"

	"github.com/safing/jess/tools"
)

// SignetSupply is cache of signets for pre-generating signets.
type SignetSupply struct {
	lock   sync.RWMutex
	caches map[string]*signetCache

	notifyEmpty    chan struct{}
	notifyFillable chan struct{}
	cacheSize      int
}

type signetCache struct {
	sync.Mutex
	tool *tools.Tool

	stock          []*jess.Signet
	stockIterator  int
	stockFillLevel int
}

// NewSignetSupply returns a new empty *SignetSupply. `cacheSize` specifies how many Signets to cache at maximum (min 1).
func NewSignetSupply(cacheSize int) *SignetSupply {
	if cacheSize < 1 {
		cacheSize = 1
	}

	return &SignetSupply{
		caches:         make(map[string]*signetCache),
		notifyEmpty:    make(chan struct{}, 1),
		notifyFillable: make(chan struct{}, 1),
		cacheSize:      cacheSize,
	}
}

// GetSignet returns a new signet from the supply.
func (supply *SignetSupply) GetSignet(scheme string) (*jess.Signet, error) {
	supply.lock.RLock()
	cache, ok := supply.caches[scheme]
	supply.lock.RUnlock()

	// init
	if !ok {
		// get tool
		tool, err := tools.Get(scheme)
		if err != nil {
			return nil, err
		}
		// create new cache
		cache = &signetCache{
			tool:  tool,
			stock: make([]*jess.Signet, supply.cacheSize),
		}
		// save to index
		supply.lock.Lock()
		supply.caches[scheme] = cache
		supply.lock.Unlock()
	}

	signet := cache.get()

	// returned signet from supply
	if signet != nil {
		// notify that supply can be filled again
		select {
		case supply.notifyFillable <- struct{}{}:
		default:
		}

		return signet, nil
	}

	// notify that supply is empty
	select {
	case supply.notifyEmpty <- struct{}{}:
	default:
	}

	// generate ad hoc
	signet = jess.NewSignetBase(cache.tool)
	err := signet.GenerateKey()
	if err != nil {
		return nil, err
	}

	return signet, nil
}

func (sc *signetCache) get() *jess.Signet {
	sc.Lock()
	defer sc.Unlock()

	// get slot
	signet := sc.stock[sc.stockIterator]
	if signet == nil {
		return nil
	}

	// reset slot
	sc.stock[sc.stockIterator] = nil

	// debugging
	// fmt.Printf("returning %s: iter=%d fill=%d\n", sc.tool.Info.Name, sc.stockIterator, sc.stockFillLevel-1)

	// adjust helpers
	sc.stockFillLevel--
	sc.stockIterator = (sc.stockIterator + 1) % len(sc.stock)

	return signet
}

// Fill fills all caches with new Signets in the specified amount (up to the cache size), and returns whether the caches are now full. This function is meant to be called periodically (when there is time) with small values for `amount` until the supply is full.
func (supply *SignetSupply) Fill(amount int) (full bool, lastErr error) {
	supply.lock.RLock()
	defer supply.lock.RUnlock()

	full = true
	for _, cache := range supply.caches {
		cacheIsFull, err := cache.fill(amount)
		if err != nil {
			lastErr = err
		}
		if !cacheIsFull {
			full = false
		}
	}

	return
}

func (sc *signetCache) fill(amount int) (full bool, err error) {
	sc.Lock()
	defer sc.Unlock()

	var signet *jess.Signet
	fillUpTo := sc.stockFillLevel + amount

	// check upper bound
	if fillUpTo > len(sc.stock) {
		fillUpTo = len(sc.stock)
	}

	// generate new signets until wanted fill amount is reached
	for i := (sc.stockIterator + sc.stockFillLevel) % len(sc.stock); // start at first empty index
	sc.stockFillLevel < fillUpTo;                                    // continue until fill amount is reached
	i = (i + 1) % len(sc.stock) /* increase i, but wrap to start */ {
		// get signet from slot
		signet = sc.stock[i]

		// debugging
		// fmt.Printf("filling %s: i=%d iter=%d fill=%d upto=%d signet=%+v\n", sc.tool.Info.Name, i, sc.stockIterator, sc.stockFillLevel, fillUpTo, signet)

		if signet != nil {
			// full
			return true, nil
		}

		// generate new
		signet = jess.NewSignetBase(sc.tool)
		err := signet.GenerateKey()
		if err != nil {
			return false, err
		}

		// reassign
		sc.stock[i] = signet
		sc.stockFillLevel++
	}

	return sc.stockFillLevel == len(sc.stock), nil
}

// Status holds status information about a signet supply.
type Status struct {
	TotalSize int
	FillLevel int
}

// Status returns current status information.
func (supply *SignetSupply) Status() *Status {
	supply.lock.RLock()
	defer supply.lock.RUnlock()

	status := &Status{
		TotalSize: supply.cacheSize * len(supply.caches),
	}

	// get current fill level
	for _, cache := range supply.caches {
		cache.status(status)
	}

	return status
}

func (sc *signetCache) status(status *Status) {
	sc.Lock()
	defer sc.Unlock()

	status.FillLevel += sc.stockFillLevel
}
