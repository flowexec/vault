package vault

import "os"

func expandPath(path string) string {
	if path == "" {
		return ""
	}

	switch path[0] {
	case '~':
		homeDir, _ := os.UserHomeDir()
		return homeDir + path[1:]
	case '/':
		return path
	case '.':
		wd, _ := os.Getwd()
		return wd + "/" + path[1:]
	case '$':
		envVar := path[1:]
		if value, exists := os.LookupEnv(envVar); exists {
			return value
		}
	default:
		wd, _ := os.Getwd()
		if wd[len(wd)-1] == '/' {
			return wd + path
		} else {
			return wd + "/" + path
		}
	}
	return path
}
