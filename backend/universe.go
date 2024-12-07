package main

type Universe map[uint64]bool

func NewUniverse(ui []uint64) Universe {
	u := make(Universe)

	for _, i := range ui {
		u[i] = true
	}

	return u
}

func (u Universe) SliceMatches(ui []uint64) []uint64 {
	usm := []uint64{}

	for _, i := range ui {
		if !u[i] {
			continue
		}

		usm = append(usm, i)
	}

	return usm
}
