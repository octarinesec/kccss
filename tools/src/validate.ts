import { Risk } from "./rules/Risk";
import { Remediation } from "./rules/Remediation";
const fs = require('fs');
const program = require('commander');

program
  .option('-s, --save', 'Validate and save the update file')
  .option('-r, --risk', 'Validate Risks only')
  .option('-e, --remediation', 'Validate Remediations only');

program.parse(process.argv);

var scanDir = function(base : string, callback : any) {
    fs.readdir(base, (err : any, entries : string[]) => {
        entries.forEach((entry : string) => {
            if (entry.endsWith("yaml"))
                callback(`${base}/${entry}`);
            else if (fs.lstatSync(`${base}/${entry}`).isDirectory()) {
                scanDir(`${base}/${entry}`, callback);
            }

        });
    });
}

// Validate risk rules
if (program.risk || ! program.remediation) {
    scanDir('../rules/risks', (file: string) => {
        var risk = new Risk(file);

        var valid = risk.validate();
         
        try {
            risk.save(undefined, ! program.save);
        }
        catch(e) {
            console.error("Failed to save " + file);
            console.error(e);
            valid = false;
        }

        var error = valid ? '' : ' INVALID';
        console.log("Risk: " + risk.score + " - " + risk.risk + " - " + risk.title + error);
            
    });
}

// Validate remediations
if (program.remediation || ! program.risk) {
    scanDir('../rules/remediations', (file: string) => {
        var remediation = new Remediation(file);

        var valid = remediation.validate;
        
        try {
            remediation.save(undefined, ! program.save);
        }
        catch(e) {
            console.error("Failed to save " + file);
            console.error(e);
        }

        var error = valid ? '' : ' INVALID';
        console.log("Remediation: " + remediation.title + " " + remediation.vector + error);
    });
}