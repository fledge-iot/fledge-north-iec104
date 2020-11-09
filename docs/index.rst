IEC 104 Server
==============

The *fledge-north-iec104* plugin is a rather unusual north plugin as it does not send data to a system, but rather acts as a server from which other systems can pull data from Fledge. This is slightly at odds with the concept of short running tasks for sending north and does require a little more configuration when creating the North IEC 104 server.

The process of creating a North IEC 104 Server start as with any other north setup by selecting the *North* option in the left-hand menu bar, then press the add icon in the top right corner. In the *North Plugin* list select the iec104 option.

In addition to setting a name for this task it is recommended to set the *Repeat* interval to a higher value than the 30 second default as we will be later setting the maximum run time of the north task to a higher value. Once complete click on *Next* and move on to the configuration of the plugin itself.

This second page allows for the setting of the configuration within the IEC 104 server.

  - **Server Name**: The name the IEC 104 server will report itself as to any client that connects to it.

Once you have completed your configuration click *Next* to move to the final page and then enable your north task and click *Done*.

The only step left is to modify the duration for which the task runs. This can only be done **after** it has been run for the first time. Enter your *North* task list again and select the IEC 104 North that you just created. This will show the configuration of your North task. Click on the *Show Advanced Config* option to display your advanced configuration.

The *Duration* option controls how long the north task will run before stopping. Each time it stops any client connected to the Fledge IEC 104 server will be disconnected, in order to reduce the disconnect/reconnect volumes it is advisable to set this to a value greater than the 60 second default. In our example here we set the repeat interval to one hour, so ideally we should set the duration to an hour also such that there is no time when an IEC 104 server is not running. *Duration* is set in seconds, so should be 3600 in our example.
