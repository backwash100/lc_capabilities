# LimaCharlie Core Detection Capabilities

These detections and hunters are designed to be used in conjunction with [LimaCharlie](https://github.com/refractionpoint/limacharlie).

## How to Use
To load or unload capabilities see the [LimaCharlie Wiki](https://github.com/refractionPOINT/limacharlie/wiki/Load-Unload-Capabilities).

## What to Load

### Major Events From Sensor
As a basis, to generate detections from "major" events from the sensor, it is recommended to run the patrol_from_sensor.py patrol.
It only loads capabilities that highlight major events like process hollowing, hidden modules and Yara signature hits.

### Other Events
If you only run OSX, or Windows, you can run the patrol_win or patrol_osx patrols to only activate detections for these platforms.

If your environment is a mix of all platforms, run the patrol_all to activate everything.

The patrol_test is only used for tests for specific capabilities.

## Fork This!
It's likely you have some ideas for detections or things that need to be custom to your environment. If that's the case just
fork this repo.
