package main

// Wrap a function that does not error to an a infailable handler that will always return "nil" for an error
func infailableHandler[T any](fn func(e T)) func(e T) error {
	return func(e T) error {
		fn(e)
		return nil
	}
}
