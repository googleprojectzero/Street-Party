To record a stream in WebRTC:

1) Apply record.diff to your WebRTC tree, making sure to replace the path in the file with a valid one
2) Run a stream on WebRTC
3) The dump files will be output at the path you speified

To replay a stream:

1) Build video_replay in your WebRTC tree:

	gn gen out/Default
	ninja -C out/Default video_replay

2) Run video_replay:

	video_replay --input_file rtp_file_dump --config_file rtp_file_config
