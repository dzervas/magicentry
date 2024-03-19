const canvasSize = 512;
const canvasMiddle = canvasSize / 2;
const strokeSize = 35;
const backgroundColor = 220;

function normalFill() {
	fill(31, 41, 55);
}

function normalStroke() {
	noErase();
	stroke(31, 41, 55);
	strokeWeight(strokeSize);
}

function backgroundStroke() {
	noErase();
	stroke(backgroundColor);
	strokeWeight(strokeSize);
}

function marginStroke() {
	// erase(0);
	stroke(backgroundColor)
	strokeWeight(2 * strokeSize);
}

function roundedSquare(size, margin, fillet) {
	marginStroke();
	rect(margin, margin, size - 2*margin, size - 2*margin, fillet);
	normalStroke();
	rect(margin, margin, size - 2*margin, size - 2*margin, fillet);
}

function setup() {
	createCanvas(canvasSize, canvasSize);
}

function outerSquare() {
	const margin = 1 * canvasSize / 10;
	const fillet = margin;

	roundedSquare(canvasSize, margin, fillet);
}

function hatBase() {
	const position = 3 * canvasSize / 5;
	const width = 4 * canvasSize / 6;
	const height = 1 * canvasSize / 7;
	const margin = width / 16;

	marginStroke();
	ellipse(canvasMiddle, position, width + margin, height + margin);
	normalStroke();
	ellipse(canvasMiddle, position, width, height);
}

function lock() {
	const size = 1 * canvasSize / 6;
	const pos_x = canvasMiddle - (size / 2);
	const pos_y = canvasSize * 8 / 12;
	const fillet = 1 * size / 10;

	// pad
	const pad_size = size * 4 / 5;
	const pad_pos_y = pos_y - (pad_size / 2) + (2 * fillet);
	const pad_width = size - fillet;
	marginStroke();
	strokeWeight(4 * strokeSize / 3);
	arc(canvasMiddle, pad_pos_y, pad_size, pad_size, 180, 0)

	// Main square
	marginStroke();
	rect(pos_x, pos_y, size, size, fillet);
	normalFill();
	normalStroke();
	rect(pos_x, pos_y, size, size, fillet);
	noFill()


	normalStroke();
	strokeWeight(strokeSize/2);
	arc(canvasMiddle, pad_pos_y, pad_size, pad_size, 180, 0)

	// Keyway
	const keyway_pos_y = pos_y + (size * 2 / 6);
	const keyway_diam = size / 3;
	const keyway_width = size * 3 / 10;
	const keyway_height = size * 4 / 10;
	noStroke();
	fill(backgroundColor)
	circle(canvasMiddle, keyway_pos_y, keyway_diam)
	quad(
		canvasMiddle - (keyway_width / 5), keyway_pos_y,
		canvasMiddle + (keyway_width / 5), keyway_pos_y,
		canvasMiddle + (keyway_width / 2), keyway_pos_y + keyway_height,
		canvasMiddle - (keyway_width / 2), keyway_pos_y + keyway_height
	)
	noFill()


}

function draw() {
	// background(backgroundColor);
	noFill();
	stroke(31, 41, 55);
	strokeWeight(strokeSize);
	angleMode(DEGREES);

	outerSquare();
	hatBase();
	lock()
}
