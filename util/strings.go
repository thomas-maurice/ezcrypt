package util

func SplitBase64(s string) []string {
	size := 64
	ss := make([]string, 0, len(s)/size+1)
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		ss, s = append(ss, s[:size]), s[size:]

	}
	return ss
}
