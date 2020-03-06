import * as fs from 'fs';
import * as yaml from 'js-yaml';


export enum impact {
    None = 'None',
    Low = 'Low',
    Medium = 'Medium',
    High = 'High'
}

enum exploitabilityImpact {
    VeryLow = 'Very Low',
    Low = 'Low',
    Moderate = 'Moderate',
    High = 'High'
}

export enum attackVector {
    Local = 'Local',
    Remote = 'Remote'
}

export enum scopeImpact {
    None = 'Container',
    Container = 'Container',
    Host = 'Host',
    Cluster = 'Cluster'
}

enum riskCategory {
    Low = 2,
    Medium = 5,
    High = 10,
}

export interface Impact {
    impact: impact;
    description: string;
}

interface Exploitability {
    impact: exploitabilityImpact;
    description: string;
}

export interface AttackVector {
    impact: attackVector;
    description: string;
};

export interface Scope {
    impact: scopeImpact;
    category: string;
    description: string;
}

// score constants
var impactScore : any = {
	High: 0.56,
	Low: 0.22,
    None: 0
};

const scopeFactor : any = {
    Container: 0.25,
    None: 0.25,
    Host: 1.0,
    Cluster: 1.0
};

const attackVectorFactor : any = {
    Remote: 0.85,
    Local: 0.55
};

const exploitabilityFactor : any = {
    High: 0.54,
    Moderate: 0.4,
    Low: 0.1,
    'Very Low': 0.05,
    VeryLow: 0.05
}

const impactConst : number = 4;
const exploitabilityConst : number = 9;

// common parts between risks and remediations
export class Rule {
    name: string = '';
    type: string = 'rremediation';
    id: string = '';
    revision: number = 1;
    category: string = '';
    rule: string = '';
    title: string = '';
    description: string = '';
    shortDescription: string = '';
    availability: Impact = {impact: impact.None, description: ""};
    confidentiality: Impact = {impact: impact.None, description: ""};
    integrity: Impact = {impact: impact.None, description: "" };
    scope: Scope = {impact: scopeImpact.None, category: "", description: ""};
    attackVector: AttackVector = {impact: attackVector.Local, description: ""};
    vector: string = "";
    references?: any;
    protected file : string = "";

    protected getImpact(doc: any) : Impact {
        var result : Impact =  {impact: impact.None, description: ""};

        result.impact = impact[<impact>doc.impact];
        result.description = doc.description ? doc.description : '';

        return result;
    }

    protected getAttackVector(doc: any) : AttackVector {
        var result : AttackVector = {impact: attackVector.Local, description: ""};

        result.impact = attackVector[<attackVector>doc.impact];
        result.description = doc.description ? doc.description : '';

        return result;
    }

    protected getScope(doc: any) : Scope {
        var result : Scope = {impact: scopeImpact.None, description: "", category: ""};
        //@ts-ignore
        result.impact = scopeImpact[doc.impact];
        result.description = doc.description ? doc.description : '';
        result.category = doc.category ? doc.category : '';

        return result;
    }

    protected computeVector() : string {
        var vector : string = "AV:" + this.getVectorAttack(this.attackVector.impact);
        vector += "/S:" + this.getVectorScope(this.scope.impact);

        vector += "/C:" + this.getVectorImpact(this.confidentiality.impact);
        vector += "/I:" + this.getVectorImpact(this.integrity.impact);
        vector += "/A:" + this.getVectorImpact(this.availability.impact);

        return vector;
    }

    private getVectorScope(value: scopeImpact) {
        var vector: string = "";
        switch(value) { 
            case scopeImpact.None: { 
                vector = 'N';  
                break; 
            } 
            case scopeImpact.Host: { 
                vector = 'H'; 
                break; 
            }
            case scopeImpact.Cluster: { 
                vector = 'C'; 
                break; 
            }
        }

        return vector;
    }

    private getVectorAttack(value: attackVector) {
        var vector: string = "";
        switch(value) { 
            case attackVector.Local: { 
                vector = 'L';  
                break; 
            } 
            case attackVector.Remote: { 
                vector = 'N'; 
                break; 
            } 
        }

        return vector;
    }

    private getVectorImpact(value: impact) {
        var vector: string = "";
        switch(value) { 
            case impact.Low: { 
                vector = 'L';  
                break; 
            } 
            case impact.Medium: { 
                vector = 'M'; 
                break; 
            } 
            case impact.High: { 
                vector = 'H'; 
                break; 
            } 
            default: { 
                vector = 'N'; 
                break; 
            } 
        }

        return vector;
    }

    save(target : string = this.file, test : boolean = false) {
        // dirty cleanup
        var object = this;
        delete object.file;

        if (object.references == '')
            delete object.references;

        const dump = yaml.safeDump(object);

        if (target == '') {
            console.log(dump);
            return;
        }

        if (test == false)
            fs.writeFileSync(target, dump, { encoding: "utf8" });
    }
}

// Represents a risk rule
export class Risk extends Rule {
    type: string = 'risk';
    exploitability: Exploitability = {impact: exploitabilityImpact.VeryLow, description: ""};
    
    baseScore: number = 0;
    exploitabilitScore: number = 0;
    score: number = 0;
    risk: string = 'Low';

    constructor(file : string) {
        super();
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
        this.exploitability = this.getExploitability(doc.exploitability);
        this.attackVector = this.getAttackVector(doc.attackVector);
        this.scope = this.getScope(doc.scope);
        this.references = doc.references ? doc.references: '';

        this.validate();

        // compute additional info
        this.vector = this.computeVector();
        this.baseScore = Math.round(10 * this.computeBaseScore()) / 10;
        this.exploitabilitScore =  Math.round(10 * this.computeExploitabilityScore()) / 10;
        this.score =  Math.round(10 * (this.baseScore + this.exploitabilitScore)) / 10;
        this.risk = this.computeRisk();
    }

    protected computeVector() : string {
        var vector = super.computeVector();
        vector += "/E:" + this.getVectorExploitability(this.exploitability.impact);

        return vector;
    }

    private getVectorExploitability(value: exploitabilityImpact) {
        var vector: string = "";
        switch(value) { 
            case exploitabilityImpact.VeryLow: { 
                vector = 'VL';  
                break; 
            } 
            case exploitabilityImpact.Low: { 
                vector = 'L'; 
                break; 
            }
            case exploitabilityImpact.Moderate: { 
                vector = 'M'; 
                break; 
            }
            case exploitabilityImpact.High: { 
                vector = 'H'; 
                break; 
            }
        }

        return vector;
    }

    private getExploitability(doc: any) : Exploitability {
        var result : Exploitability = {impact: exploitabilityImpact.VeryLow, description: ""};
        //@ts-ignore
        result.impact = exploitabilityImpact[<exploitabilityImpact>doc.impact.replace(' ', '')];
        result.description = doc.description ? doc.description : '';

        return result;
    }

    private computeBaseScore() : number {
        return scopeFactor[this.scope.impact.valueOf()] *  impactConst * 
            (1 - ((1 - impactScore[this.confidentiality.impact.valueOf()]) * 
            (1 - impactScore[this.integrity.impact.valueOf()]) *
            (1 - impactScore[this.availability.impact.valueOf()])));
    }

    private computeExploitabilityScore() : number {
        return exploitabilityConst * attackVectorFactor[this.attackVector.impact.valueOf()] * exploitabilityFactor[this.exploitability.impact.valueOf()];
    }

    private computeRisk() : string {
        if (this.score <= riskCategory.Low) {
            return 'Low';
        }
        else if (this.score <= riskCategory.Medium) {
            return 'Medium';
        }
        else {
            return "High";
        }
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