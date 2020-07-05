# reorg

reorg is a TUN-to-TUN packet exchanging software working at network layer to simualte a network interface card and create a smooth link between endpoints.

reorg adds extra latency to the link between a communication pair, in exchange for smoothness of transfer. TCP algorithm will treat this link as a long fat pipe insteading of packet lost when jitter happens.
