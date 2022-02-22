package main

import (
	"fmt"
)

func NewDevice(name, deviceType string) string {
	return "100," + name + "," + deviceType
}

func Measurement(fragment, series, unit, time string, value float64) string {

	msg := fmt.Sprintf("200,%s,%s,%f,%s", fragment, series, value, unit)
	if time != "" {
		msg = msg + "," + time
	}
	return msg
}

func Event(eventType, text, time string) string {
	msg := "400," + eventType + "," + text
	if time != "" {
		msg = msg + "," + time
	}
	return msg
}

func DeviceInformation(serialNumber, hardwareModel, revision string) string {
	return "110," + serialNumber + "," + hardwareModel + "," + revision
}
