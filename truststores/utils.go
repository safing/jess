package truststores

func stringInSlice(s string, a []string) bool {
	for _, entry := range a {
		if entry == s {
			return true
		}
	}
	return false
}
