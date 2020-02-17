import {Rule, Impact, impact, attackVector, Scope, scopeImpact} from "./Risk"
import * as fs from 'fs';
import * as yaml from 'js-yaml';


export class Remediation extends Rule {
    constructor(file : string) {
        super()
        this.file = file;
        var doc = yaml.safeLoad(fs.readFileSync(file, 'utf8'));

        // parse document
        this.name = doc.name ? doc.name : '';
        this.type = doc.type ? doc.type : 'risk';
        this.id = doc.id ? doc.id : '';
        this.revision = doc.revision ? doc.revision : 1;
        this.title = doc.title ? doc.title : '';
        this.description = doc.description ? doc.description : '';
        this.shortDescription = doc.shortDescription ? doc.shortDescription : '';
        this.availability = this.getImpact(doc.availability);
        this.confidentiality = this.getImpact(doc.confidentiality);
        this.integrity = this.getImpact(doc.integrity);
        this.attackVector = this.getAttackVector(doc.attackVector);
        this.scope = this.getScope(doc.scope);

        this.validate();

        // compute additional info
        this.vector = this.computeVector();
    }

    validate() : boolean {
        if (this.availability.impact == impact.None && this.confidentiality.impact == impact.None && this.integrity.impact == impact.None) {
            // Need at least 1 impact
            console.error("Missing at least 1 impact");

            return false;
        }

        if (this.availability.impact != impact.None && this.availability.description == "") {
            console.error("Availability description is missing");

            return false;
        }
        
        return true;
    }
}