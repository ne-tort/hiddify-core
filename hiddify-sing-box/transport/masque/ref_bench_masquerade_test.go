package masque



// masquerade-shaped architectural duplex ceiling (unified concurrent Write + WriteTo, 64 KiB buf).



import (

	"net"

	"time"



	strm "github.com/sagernet/sing-box/transport/masque/stream"

)



func benchMasqueradeDuplexMinMbps(duration time.Duration) (down, up, minLeg float64) {

	client, server := net.Pipe()

	payload := make([]byte, 256*1024)



	go masqueradeShapeServerLoop(server, payload)



	down, up, minLeg, err := measureRefConnDuplexMbps(benchConnWriteTo{client}, duration)

	_ = client.Close()

	if err != nil {

		return 0, 0, 0

	}

	return down, up, minLeg

}



// masqueradeShapeServerLoop drains upload (recv_body) while pumping download (send_body) on the peer leg.

func masqueradeShapeServerLoop(server net.Conn, payload []byte) {

	defer server.Close()

	drainBuf := make([]byte, strm.RelayTunnelBufLen)

	go func() {

		for {

			if _, err := server.Read(drainBuf); err != nil {

				return

			}

		}

	}()

	for i := 0; i < 1<<20; i++ {

		if _, err := server.Write(payload); err != nil {

			return

		}

	}

}



func benchMasqueradeDuplexMinMbpsOnly(duration time.Duration) float64 {

	_, _, minLeg := benchMasqueradeDuplexMinMbps(duration)

	return minLeg

}


