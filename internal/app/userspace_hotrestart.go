package app

func userspaceWorkerPreserveOnClose() bool {
	return shouldPreserveUserspaceWorkersOnClose()
}
