package filesig

// AddYAMLChecksum adds a checksum to a yaml file.
func AddYAMLChecksum(data []byte, placement TextPlacement) ([]byte, error) {
	return AddTextFileChecksum(data, "#", placement)
}

// VerifyYAMLChecksum checks a checksum in a yaml file.
func VerifyYAMLChecksum(data []byte) error {
	return VerifyTextFileChecksum(data, "#")
}
