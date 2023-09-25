# semerge-te

## Merge SELinux Policy Source Files

`semerge-te` is a Python3 script that accepts SELinux source policy files and merges them into one consolidated output file.
In the general sense `semerge-te` is similar in nature to [semerge](https://github.com/djjudas21/semerge); however, different from the latter, `semerge-te` works with source policy files.
The source files referred here are `*.te` SELinux policy files formatted as per the `audit2allow` SELinux tool, part of the `policycoreutils-python` package.
`semerge-te` merges, deduplicates, and sorts all "allow" rule inputs from all the source files under a directory, to produce an output policy source file which contains the contents of all input policy files.
`semerge-te` also deduplicates all `require` `type` and `class` entries, merging all permissions for a given `class` in a group enclosed by `'{' '}'`.
One of its command-line options allows for a string with one or more source domains (source `type`(s) or source context(s)); it groups all `*.te` files in the input directory with the same source domain together and saved to the output file, with a comment line preceding each `type` group, such as `audit2allow` formatting does it. e.g.

```
#============= httpd_sys_script_exec_t ==============
allow httpd_sys_script_exec_t usr_t:file { append create entrypoint execute getattr ioctl map open read setattr unlink write };
allow httpd_sys_script_exec_t shell_exec_t:file { entrypoint execute map read };
...
```

If no input domain is given, it parses the "`#===`" lines from all input `*.te` files and creates a list of source domains (`type`). This can also be combined with a command line option (`-e`) to exclude a list of source `type`(s).
`semerge-te` also has a "trace" option to create an intermediate file with all the input "allow" source and destination `type` and destination `class` and permissions prior to merging. This can be used to troubleshooting and make sure nothing has been lost from the first stage of input processing.
`semerge-te` is capable of handling the following statements:

* `allow`
* `type`
* `class`
* `typeattribute`
* `attribute`

_Note: Other statements and all comments are ignored._
`semerge-te`outputs certain statistics, such as how many input rules were duplicates, how many were merged, and for those a snippet of the merge is also output to the screen. This allows for a quick comparison with the typical Linux commands such as `sed/cat/uniq/sort/wc` to ascertain if any rules weren't processed.

## Usage

Command-line options are case sensitive.
`-d` Directory path with the input source policy files.
`-o` Output file path where the source-policies are merged.
`-D` Input SELinux domains (`type`) to process.
`-E` Input SELinux domains (`type`) to exclude - mutually exclusive with `-D`.
`-t` Create an intermediate file with same name as the output file, except that it has a "_t" suffix to its name; this file is created after all policy files are processed but prior to merging the rules.

## Use Case

Let's say an existing large SW Web product Acme exists and a new phase is to retrofit SELinux to it; the designer chooses the proper labeling for the existing files and scripts comprising the product (say `httpd_t, httpd_sys_script_exec_t, httpd_sys_script_t`, etc). Finding the right SELinux policy rules to "allow" the execution of those domains with SELinux Enforcing can be very time consuming when attempting to manually merge multiple policy source files.
In this particular case the requirement is to store the policies in source format (`*.te`) in the repository, rather than binary. The binary policies are created during the fictional Acme at build time, and installed on the target system by means of its Linux package. Because of those reasons the original [semerge](https://github.com/djjudas21/semerge) was not a viable option.

## Execution Workflow

The typical workflow would be as follows:
_Note: The following can be performed either with SELinux in Enforcing or in Permissive mode; in the latter case, no iterations might be needed, but by Enforcing we get a definite proof that the policies worked (which would mean we reached the last iteration)._

* Trigger and AVC
* Create policies to remedy those by means of `ausearch` and `audit2allow`; e.g. in its simplest form one could tag each iteration with a timestamp, searching for kernel and user AVCs, and installing the policy; e.g.

 ```
 $ tm=$(date +"%m-%d-%H.%M.%S")
 $ ausearch -m avc      -te recent --raw | audit2allow -M my-kpol_${tm} && semodule -v -i my-kpol_${tm}.pp
 $ ausearch -m user_avc -te recent --raw | audit2allow -M my-upol_${tm} && semodule -v -i my-upol_${tm}.pp
 ```

* Repeat the process until the functionitly under test completes successfully.
   * _Note: `semerge-te` ignores the comment "`#!!!! This avc is allowed in the current policy`", meaning that it still takes its corresponding rule line into account. This comment entry typically happens as we iterate with `ausearch`; an allow rule would've been created in a previous iteration, however `ausearch` might still find the AVC in the log in subsequent ones. We want to capture all inputs, as duplicated ones are simply discarded_.
* Copy all `*.te` files under a temporary directory of your choosing, and run `semerge-te`.
   * In the fictional Acme project it was desired to split the policies into: one for all the "httpd" domains, and one other for the rest of the input domains, thus we would run it as follows (assume all input policies under a "tmp" directory under our workspace):

 ```
python3 semerge-te.py -d "~/workspace/acme/selinux/packages/tmp" -o "~/workspace/acme/selinux/packages/acme-webconfig.te" -D "httpd_sys_script_exec_t httpd_sys_script_t httpd_t"
 ```

* To capture the rest of the rules on another policy file (acme-misc.te), we ran it this way to exclude the "httpd" domains; with this command line option, `semerge-te` searches and creates a list of all input domains, and then removes the ones excluded by means of the '-E' argument.

 ```
python3 semerge-te.py -d "~/workspace/acme/selinux/packages/tmp" -o "~/workspace/acme/selinux/packages/acme-misc.te" -E "httpd_sys_script_exec_t httpd_sys_script_t httpd_t"
 ```

* Trigger another type of AVC (say another Web feature); repeat the above process with `ausearch` and `audit2allow` until the feature passes.
* Now we want to merge the new set of policies with the existing otuput files (acme_webconfig.te and acme_misc.te). To that end:
   * Erase the previous policies from the temp directory.
   * Copy the new set of policies into the temp directory.
   * Copy the previously obtained output files (acme_webconfig.te and acme_misc.te) into the temp directory.
   * Execute `semerge-te` again as shown above.
* Repeat this procedure for each "feature" to verify and resolve. With each set the output file will grow by merging the new set of policies into the previously processed ones, so it is a cumulative process.
* Once satisfied with the output policy files, build the binary policies (.pp), by executing make from the directory where the source output policies were created in the build server, e.g.:

```
make -f /usr/share/selinux/devel/Makefile acme-webconfig.pp
make -f /usr/share/selinux/devel/Makefile acme-misc.pp
```

Note: package `selinux-policy-devel` is required!

* Add the resulting binary policies into the product package and use a post-install scriplet to install them at the target system, e.g.

```
semodule -i acme-webconfig.pp
semodule -i acme-misc.pp
```

* As the product QA progresses the same procedure might need to repeat.

Note: Potentially the same QA team can execute the `ausearch`/`audit2allow` commands, making it easier for the product maintainer to just merge them with `semerge-te`.

## Caveats

The skilled SELinux developer would appreciate that there is another SELinux tool that can be used to remedy certain AVC triggers. An SELinux boolean can often have the same effect than a policy rule in some circumstances. `audit2allow` provides the information on potential SELinux booleans in lieu of the proposed "allow" rule.
> ... can be achieved by SELinux booleans that allow parts of SELinux policy to be changed at runtime, without any knowledge of SELinux policy writing. This allows changes, such as allowing services access to NFS volumes, without reloading or recompiling SELinux policy.

So the SELinux maintainer should carefully inspect the input policy files for relevant comments, before the merge process, and if a Boolean is proposed, it would be wise to set that SELinux Boolean, rather than adding a rule to the policy file. If so, simply remove the rule from the input file (or comment it out), prior to merging it, so it doesn't get processed by `semerge-te`.
An SELinux Boolean can be loaded at runtime (e.g. by means of a package post-install scriptlet):
> For example, to enable the httpd_anon_write Boolean, enter the following command as the root user:

```
setsebool -P httpd_anon_write on
```

Another caveat is that potential SELinux rule statements from `audit2allow` that are unknown by `semerge-te` are basically ignored by it. It is unlikely that more than the aforementioned statements will be output by `audit2allow`; with that in mind the statistics output by `semerge-te` can help identify unprocessed rules, and in that case either enter them manually, or else modify the code to process them automatically.

## License

`semerge-te` is licensed under the terms of the MIT license.
